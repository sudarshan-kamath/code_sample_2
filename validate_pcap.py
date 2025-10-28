#!/usr/bin/env python3
"""
Mount an FTP share read-only via curlftpfs and validate PCAP files with tshark.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence
from urllib.parse import quote


class ValidationError(Exception):
    """Raised when validation prerequisites are not met."""


def _run_command(
    command: Sequence[str],
    *,
    check: bool = True,
    capture_output: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Thin wrapper around subprocess.run with consistent defaults."""
    return subprocess.run(
        command,
        check=check,
        capture_output=capture_output,
        text=text,
    )


def _require_binary(name: str) -> str:
    """Return the absolute path to a binary, raising if it is missing."""
    path = shutil.which(name)
    if not path:
        raise ValidationError(
            f"Required binary '{name}' is not available on PATH. "
            f"Install it (e.g. sudo apt install {name})."
        )
    return path


def _is_already_mounted(mount_point: Path) -> bool:
    """Return True when mount_point is present in /proc/mounts."""
    try:
        with open("/proc/mounts", encoding="utf-8") as mounts:
            return any(line.split()[1] == str(mount_point) for line in mounts)
    except FileNotFoundError:
        return False


def _quote_credential(value: str) -> str:
    """Percent-encode credential components for an FTP URL."""
    return quote(value, safe="")


@dataclass
class ValidationResult:
    """Container that records outcome details for a single PCAP validation run."""
    file_path: Path
    ok: bool
    packet_count: Optional[int] = None
    first_frame: Dict[str, str] = field(default_factory=dict)
    stderr: str = ""
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class FTPMount:
    """Context manager that mounts an FTP path read-only via curlftpfs."""

    def __init__(
        self,
        *,
        host: str,
        remote_path: str,
        mount_point: Path,
        username: Optional[str],
        password: Optional[str],
        curlftpfs_bin: str,
        extra_mount_opts: Optional[str] = None,
    ) -> None:
        """Initialise the mount manager with remote and local configuration."""
        self.host = host
        self.remote_path = remote_path.lstrip("/")
        self.mount_point = mount_point
        self.username = username
        self.password = password
        self.curlftpfs_bin = curlftpfs_bin
        self.extra_mount_opts = extra_mount_opts
        self._mounted_here = False

    def __enter__(self) -> Path:
        """Mount the remote FTP directory and return the local mount point."""
        if not self.mount_point.exists():
            self.mount_point.mkdir(parents=True)

        if _is_already_mounted(self.mount_point):
            return self.mount_point

        cred_segment = ""
        if self.username:
            user_enc = _quote_credential(self.username)
            pass_enc = _quote_credential(self.password or "")
            cred_segment = f"{user_enc}:{pass_enc}@"

        remote = f"ftp://{cred_segment}{self.host}"
        if self.remote_path:
            remote = f"{remote}/{self.remote_path}"

        mount_opts = ["ro"]
        if self.extra_mount_opts:
            mount_opts.append(self.extra_mount_opts)

        command = [
            self.curlftpfs_bin,
            remote,
            str(self.mount_point),
            "-o",
            ",".join(mount_opts),
        ]

        try:
            _run_command(command)
            self._mounted_here = True
        except subprocess.CalledProcessError as exc:
            raise ValidationError(
                f"Failed to mount {remote} at {self.mount_point}: {exc.stderr.strip()}"
            ) from exc

        return self.mount_point

    def __exit__(self, exc_type, exc, tb) -> None:
        """Unmount the curlftpfs mount if this context manager created it."""
        if self._mounted_here:
            try:
                _run_command(
                    ["fusermount", "-u", str(self.mount_point)],
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError:
                # Surface unmount issues but keep original exception context.
                print(
                    f"Warning: failed to unmount {self.mount_point}. "
                    "You may need to run 'fusermount -u' manually.",
                    file=sys.stderr,
                )


def _collect_first_frame(tshark_bin: str, file_path: Path) -> Dict[str, str]:
    """Extract a handful of header fields from the first frame."""
    command = [
        tshark_bin,
        "-r",
        str(file_path),
        "-T",
        "json",
        "-c",
        "1",
        "-j",
        "frame",
    ]
    try:
        result = _run_command(command)
    except subprocess.CalledProcessError as exc:
        raise ValidationError(
            f"Failed to read first frame from {file_path}: {exc.stderr.strip()}"
        ) from exc

    try:
        payload = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise ValidationError(f"tshark JSON output malformed for {file_path}") from exc

    if not payload:
        return {}

    layers = payload[0].get("_source", {}).get("layers", {})
    frame_layer = layers.get("frame")
    if not isinstance(frame_layer, dict):
        return {}

    summary: Dict[str, str] = {}
    for key in (
        "frame.number",
        "frame.len",
        "frame.cap_len",
        "frame.protocols",
        "frame.time",
        "frame.time_epoch",
        "frame.offset_shift",
    ):
        value = frame_layer.get(key)
        if isinstance(value, list):
            try:
                summary[key] = str(value[0])
            except (IndexError, TypeError):
                continue
        elif value is not None:
            summary[key] = str(value)
    return summary


def _scan_for_warnings(stderr: str) -> Dict[str, List[str]]:
    """Categorise stderr output from tshark into warnings and errors."""
    warnings: List[str] = []
    errors: List[str] = []
    lowered = stderr.lower()
    if not lowered.strip():
        return {"warnings": warnings, "errors": errors}

    keywords = {
        "malformed": warnings,
        "truncated": warnings,
        "corrupt": errors,
        "error": errors,
        "failed": errors,
    }

    for line in stderr.splitlines():
        line_lower = line.lower()
        matched = False
        for key, bucket in keywords.items():
            if key in line_lower:
                bucket.append(line.strip())
                matched = True
                break
        if not matched:
            warnings.append(line.strip())

    return {"warnings": warnings, "errors": errors}


def validate_pcap(tshark_bin: str, file_path: Path) -> ValidationResult:
    """Run tshark-based checks over a single PCAP file."""
    primary_cmd = [tshark_bin, "-r", str(file_path), "-n", "-q"]
    result = ValidationResult(file_path=file_path, ok=False)

    try:
        completed = _run_command(primary_cmd)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr or ""
        buckets = _scan_for_warnings(stderr)
        result.stderr = stderr
        result.warnings = buckets["warnings"]
        result.errors = buckets["errors"] or [stderr.strip() or exc.stderr]
        return result

    result.stderr = completed.stderr or ""
    buckets = _scan_for_warnings(result.stderr)
    result.warnings = buckets["warnings"]
    result.errors = buckets["errors"]

    if result.errors:
        return result

    try:
        frame_summary = _collect_first_frame(tshark_bin, file_path)
        result.first_frame = frame_summary
    except ValidationError as exc:
        result.errors.append(str(exc))
        return result

    try:
        packet_count = _count_packets(tshark_bin, file_path)
        result.packet_count = packet_count
    except ValidationError as exc:
        result.warnings.append(str(exc))

    result.ok = not result.errors
    return result


def _count_packets(tshark_bin: str, file_path: Path) -> int:
    """Count packets by streaming tshark field output."""
    command = [
        tshark_bin,
        "-r",
        str(file_path),
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        raise ValidationError(f"Unable to launch tshark for counting packets: {exc}") from exc

    assert process.stdout is not None
    count = 0
    try:
        for _ in process.stdout:
            count += 1
    finally:
        process.stdout.close()

    stderr = ""
    if process.stderr is not None:
        stderr = process.stderr.read()
        process.stderr.close()

    returncode = process.wait()
    if returncode != 0:
        raise ValidationError(
            f"tshark returned {returncode} when counting packets for {file_path}: {stderr.strip()}"
        )

    buckets = _scan_for_warnings(stderr)
    if buckets["errors"]:
        raise ValidationError(
            f"Errors while counting packets for {file_path}: {'; '.join(buckets['errors'])}"
        )
    if buckets["warnings"]:
        raise ValidationError(
            f"Warnings while counting packets for {file_path}: {'; '.join(buckets['warnings'])}"
        )

    return count


def discover_pcaps(root: Path, patterns: Iterable[str], recursive: bool) -> List[Path]:
    """Discover PCAP files matching glob patterns from the mount root."""
    matches: List[Path] = []
    for pattern in patterns:
        if recursive:
            matches.extend(root.rglob(pattern))
        else:
            matches.extend(root.glob(pattern))
    return sorted({path.resolve() for path in matches if path.is_file()})


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Define and parse command-line arguments for the validator CLI."""
    parser = argparse.ArgumentParser(
        description="Mount an FTP share via curlftpfs and validate PCAP files with tshark.",
    )
    parser.add_argument("--ftp-host", required=True, help="FTP server hostname or IP.")
    parser.add_argument(
        "--ftp-path",
        default="/",
        help="Remote path on the FTP server to mount (default: whole root).",
    )
    parser.add_argument(
        "--username",
        default="anonymous",
        help="FTP username (default: anonymous).",
    )
    parser.add_argument(
        "--password",
        help="FTP password. Omit to read from FTP_PASSWORD environment or prompt.",
    )
    parser.add_argument(
        "--password-env",
        default="FTP_PASSWORD",
        help="Environment variable to read the password from when --password is omitted.",
    )
    parser.add_argument(
        "--mount-point",
        required=True,
        type=Path,
        help="Local directory used as the mount point (must be writable).",
    )
    parser.add_argument(
        "--pcap-pattern",
        action="append",
        default=["*.pcap", "*.pcapng"],
        help="Glob pattern for PCAP discovery (can be specified multiple times).",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively discover PCAP files (default: current directory only).",
    )
    parser.add_argument(
        "--tshark-bin",
        default="tshark",
        help="Path to tshark binary (default: tshark).",
    )
    parser.add_argument(
        "--curlftpfs-bin",
        default="curlftpfs",
        help="Path to curlftpfs binary (default: curlftpfs).",
    )
    parser.add_argument(
        "--extra-mount-opts",
        help="Additional curlftpfs mount options to append (comma-separated).",
    )
    parser.add_argument(
        "--pcap",
        action="append",
        default=[],
        help="Specific PCAP path(s) relative to the mount root to validate.",
    )
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Treat tshark warnings as errors.",
    )
    return parser.parse_args(argv)


def resolve_password(args: argparse.Namespace) -> Optional[str]:
    """Resolve FTP password precedence: CLI flag, env var, interactive prompt."""
    if args.password:
        return args.password
    env_value = os.getenv(args.password_env)
    if env_value:
        return env_value
    if args.username == "anonymous":
        return None
    try:
        return getpass.getpass("FTP password: ")
    except (EOFError, KeyboardInterrupt):
        raise ValidationError("Password is required but was not provided.")


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entrypoint for command-line execution handling mounting and validation."""
    args = parse_args(argv)

    try:
        curlftpfs_path = _require_binary(args.curlftpfs_bin)
        tshark_path = _require_binary(args.tshark_bin)
        _require_binary("fusermount")
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        return 2

    try:
        password = resolve_password(args)
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        return 2

    mount_point: Path = args.mount_point.resolve()
    remote_list: List[str] = args.pcap or []

    with FTPMount(
        host=args.ftp_host,
        remote_path=args.ftp_path,
        mount_point=mount_point,
        username=args.username,
        password=password,
        curlftpfs_bin=curlftpfs_path,
        extra_mount_opts=args.extra_mount_opts,
    ) as mounted_root:
        targets: List[Path]
        if remote_list:
            targets = [mounted_root / rel_path for rel_path in remote_list]
        else:
            targets = discover_pcaps(
                mounted_root,
                args.pcap_pattern,
                recursive=args.recursive,
            )

        if not targets:
            print("No PCAP files found to validate.", file=sys.stderr)
            return 1

        exit_code = 0
        for file_path in targets:
            relative = file_path.relative_to(mounted_root)
            if not file_path.exists():
                print(f"[missing] {relative}", file=sys.stderr)
                exit_code = max(exit_code, 1)
                continue
            result = validate_pcap(tshark_path, file_path)
            status = "OK" if result.ok else "FAIL"
            print(f"[{status}] {relative}")
            if result.packet_count is not None:
                print(f"  packets: {result.packet_count}")
            if result.first_frame:
                for key, value in result.first_frame.items():
                    print(f"  {key}: {value}")
            if result.warnings:
                for warning in result.warnings:
                    line = f"  warning: {warning}"
                    print(line)
                    if args.fail_on_warning:
                        result.ok = False
            if result.errors:
                for err in result.errors:
                    print(f"  error: {err}", file=sys.stderr)
            if not result.ok:
                exit_code = max(exit_code, 1)
        return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
