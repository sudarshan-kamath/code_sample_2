#!/usr/bin/env python3
"""Download PCAP files from FTP and validate them locally with tshark."""

from __future__ import annotations

import argparse
import ftplib
import fnmatch
import getpass
import json
import os
import posixpath
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Type


class ValidationError(Exception):
    """Raised when validation prerequisites are not met."""


def _run_command(
    command: Sequence[str],
    *,
    check: bool = True,
    capture_output: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Execute a command with consistent defaults."""
    return subprocess.run(
        command,
        check=check,
        capture_output=capture_output,
        text=text,
    )


def _require_binary(name: str) -> str:
    """Return the absolute path for a binary, raising if missing."""
    path = shutil.which(name)
    if not path:
        raise ValidationError(
            f"Required binary '{name}' is not available on PATH. "
            f"Install it (e.g. sudo apt install {name})."
        )
    return path


def _scan_for_warnings(stderr: str) -> Dict[str, List[str]]:
    """Classify stderr lines from tshark into warnings vs errors."""
    warnings: List[str] = []
    errors: List[str] = []
    if not stderr:
        return {"warnings": warnings, "errors": errors}

    keywords = {
        "malformed": errors,
        "truncated": errors,
        "corrupt": errors,
        "error": errors,
        "failed": errors,
    }

    for raw_line in stderr.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        line_lower = line.lower()
        matched = False
        for keyword, bucket in keywords.items():
            if keyword in line_lower:
                bucket.append(line)
                matched = True
                break
        if not matched:
            warnings.append(line)

    return {"warnings": warnings, "errors": errors}


def _collect_first_frame(tshark_bin: str, file_path: Path) -> Dict[str, str]:
    """Extract selected header fields from the first frame."""
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
        completed = _run_command(command)
    except subprocess.CalledProcessError as exc:
        raise ValidationError(
            f"Failed to read first frame from {file_path}: {exc.stderr.strip()}"
        ) from exc

    try:
        payload = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise ValidationError(f"tshark JSON output malformed for {file_path}") from exc

    if not payload:
        return {}

    first = payload[0]
    layers = first.get("_source", {}).get("layers", {})
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
            if value:
                summary[key] = str(value[0])
        elif value is not None:
            summary[key] = str(value)
    return summary


def _count_packets(tshark_bin: str, file_path: Path) -> int:
    """Count packets by streaming frame numbers from tshark."""
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


@dataclass
class ValidationResult:
    """Container for tshark validation output."""

    file_path: Path
    ok: bool
    packet_count: Optional[int] = None
    first_frame: Dict[str, str] = field(default_factory=dict)
    stderr: str = ""
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def validate_pcap(tshark_bin: str, file_path: Path) -> ValidationResult:
    """Run the tshark validation pipeline on a local PCAP file."""
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
        result.first_frame = _collect_first_frame(tshark_bin, file_path)
    except ValidationError as exc:
        result.errors.append(str(exc))
        return result

    try:
        result.packet_count = _count_packets(tshark_bin, file_path)
    except ValidationError as exc:
        result.warnings.append(str(exc))

    malformed_cmd = [
        tshark_bin,
        "-r",
        str(file_path),
        "-Y",
        "_ws.malformed",
        "-c",
        "1",
        "-T",
        "fields",
        "-E",
        "separator=|",
        "-e",
        "frame.number",
        "-e",
        "frame.col_info",
    ]
    malformed_proc = subprocess.run(
        malformed_cmd,
        check=False,
        capture_output=True,
        text=True,
    )
    malformed_output = (malformed_proc.stdout or "").strip()
    if malformed_proc.returncode not in {0, 1}:
        result.warnings.append(
            f"Malformed frame probe failed for {file_path}: {malformed_proc.stderr.strip()}"
        )
    elif malformed_output:
        frame_info = malformed_output.split("|", maxsplit=1)
        frame_number = frame_info[0].strip()
        detail = frame_info[1].strip() if len(frame_info) > 1 else ""
        message = f"Malformed frame detected: frame {frame_number}"
        if detail:
            message = f"{message}: {detail}"
        result.errors.append(message)

    result.ok = not result.errors
    return result


@dataclass
class RemoteFile:
    """Represents a remote FTP file selected for download."""

    relative_path: str


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments for the FTP download workflow."""
    parser = argparse.ArgumentParser(
        description="Download PCAPs over FTP and validate them locally with tshark.",
    )
    parser.add_argument("--ftp-host", required=True, help="FTP server hostname or IP.")
    parser.add_argument(
        "--port",
        type=int,
        default=21,
        help="FTP server port (default: 21).",
    )
    parser.add_argument(
        "--ftp-path",
        default="/",
        help="Remote directory on the FTP server to inspect (default: /).",
    )
    parser.add_argument(
        "--username",
        default="anonymous",
        help="FTP username (default: anonymous).",
    )
    parser.add_argument(
        "--password",
        help="FTP password; falls back to environment variable or prompt.",
    )
    parser.add_argument(
        "--password-env",
        default="FTP_PASSWORD",
        help="Environment variable to read the password from when --password is omitted.",
    )
    parser.add_argument(
        "--use-ftps",
        action="store_true",
        help="Use explicit FTPS (FTP over TLS) for the connection.",
    )
    parser.add_argument(
        "--download-dir",
        required=True,
        type=Path,
        help="Local directory where captures will be downloaded and retained.",
    )
    parser.add_argument(
        "--pcap-pattern",
        action="append",
        default=["*.pcap", "*.pcapng"],
        help="Glob pattern for PCAP discovery (can be supplied multiple times).",
    )
    parser.add_argument(
        "--tshark-bin",
        default="tshark",
        help="Path to the tshark binary (default: tshark).",
    )
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Treat tshark warnings as errors.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Socket timeout for FTP operations in seconds (default: 60).",
    )
    return parser.parse_args(argv)


def resolve_password(args: argparse.Namespace) -> Optional[str]:
    """Resolve FTP password from CLI, environment, or interactive prompt."""
    if args.password:
        return args.password
    env_value = os.getenv(args.password_env)
    if env_value:
        return env_value
    if args.username == "anonymous":
        return None
    try:
        return getpass.getpass("FTP password: ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise ValidationError("Password is required but was not provided.") from exc


def discover_remote_pcaps(
    ftp: ftplib.FTP,
    patterns: Iterable[str],
) -> List[RemoteFile]:
    """Return a list of remote files matching provided patterns."""
    results: List[RemoteFile] = []
    pattern_list = list(patterns)

    entries: List[tuple[str, Optional[dict]]] = []
    supports_mlsd = hasattr(ftp, "mlsd")
    if supports_mlsd:
        try:
            entries = [(name, facts) for name, facts in ftp.mlsd()]  # type: ignore[attr-defined]
        except ftplib.error_perm:
            entries = []
        except AttributeError:
            entries = []
    if not entries:
        try:
            names = ftp.nlst()
        except ftplib.error_perm as exc:
            raise ValidationError(f"Unable to list directory '.': {exc}") from exc
        entries = [(posixpath.basename(name.rstrip("/")), None) for name in names]

    for name, facts in entries:
        if not name or name in {".", ".."}:
            continue
        is_dir = False
        if facts and isinstance(facts, dict):
            is_dir = facts.get("type", "") in {"dir", "cdir", "pdir"}
        if is_dir:
            continue
        if any(fnmatch.fnmatch(name, pattern) for pattern in pattern_list):
            results.append(RemoteFile(name))

    unique = {entry.relative_path: entry for entry in results}
    return [unique[key] for key in sorted(unique)]


def download_remote_file(
    ftp: ftplib.FTP,
    remote_file: RemoteFile,
    destination_root: Path,
) -> Path:
    """Download a single remote file into the destination directory."""
    local_path = destination_root / Path(remote_file.relative_path)
    local_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(local_path, "wb") as handle:
            def _write(chunk: bytes) -> None:
                handle.write(chunk)

            ftp.retrbinary(f"RETR {remote_file.relative_path}", _write)
    except ftplib.error_perm as exc:
        raise ValidationError(
            f"Failed to download '{remote_file.relative_path}': {exc}"
        ) from exc
    except OSError as exc:
        raise ValidationError(f"Unable to write to '{local_path}': {exc}") from exc

    return local_path


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entrypoint for downloading files and invoking the validator."""
    args = parse_args(argv)

    try:
        tshark_path = _require_binary(args.tshark_bin)
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        return 2

    try:
        password = resolve_password(args)
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        return 2

    destination_root = args.download_dir.resolve()
    destination_root.mkdir(parents=True, exist_ok=True)

    ftp_cls: Type[ftplib.FTP]
    if args.use_ftps:
        ftp_cls = ftplib.FTP_TLS
    else:
        ftp_cls = ftplib.FTP

    try:
        with ftp_cls() as ftp:
            ftp.connect(args.ftp_host, args.port, timeout=args.timeout)
            if args.use_ftps and isinstance(ftp, ftplib.FTP_TLS):
                ftp.auth()
            ftp.login(args.username, password or "")
            if args.use_ftps and isinstance(ftp, ftplib.FTP_TLS):
                ftp.prot_p()
            if args.ftp_path and args.ftp_path != "/":
                ftp.cwd(args.ftp_path)

            remote_files = discover_remote_pcaps(
                ftp,
                args.pcap_pattern,
            )
            if not remote_files:
                print("No PCAP files found to download.", file=sys.stderr)
                return 1

            exit_code = 0
            for remote_file in remote_files:
                print(f"[download] {remote_file.relative_path}")
                local_path = download_remote_file(ftp, remote_file, destination_root)
                result = validate_pcap(tshark_path, local_path)

                status_ok = result.ok and not (args.fail_on_warning and result.warnings)
                status = "OK" if status_ok else "FAIL"
                print(f"[{status}] {remote_file.relative_path}")
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
                if not result.ok or (args.fail_on_warning and result.warnings):
                    exit_code = max(exit_code, 1)
            return exit_code
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        return 2
    except ftplib.all_errors as exc:
        print(f"FTP error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
