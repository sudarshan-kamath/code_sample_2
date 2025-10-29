#!/usr/bin/env python3
"""Download PCAP files from FTP and validate them locally with tshark."""

from __future__ import annotations

import argparse
import ftplib
import fnmatch
import json
import posixpath
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Type


RESET = "\033[0m"
COLOR_OK = "\033[92m"
COLOR_FAIL = "\033[91m"
USE_COLOR = sys.stderr.isatty()


class ValidationError(Exception):
    """Raised when validation prerequisites are not met."""


def _color(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color}{text}{RESET}"


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

    patterns = (
        ("malformed", errors, "Malformed frame: {line}"),
        ("truncated", warnings, "Packet truncated during capture: {line}"),
        ("cut short", warnings, "Packet truncated during capture: {line}"),
        ("corrupt", errors, "Corrupted data detected: {line}"),
        ("error", errors, "tshark error: {line}"),
        ("failed", errors, "Operation failed: {line}"),
    )

    for raw_line in stderr.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        line_lower = line.lower()
        matched = False
        for keyword, bucket, message in patterns:
            if keyword in line_lower:
                bucket.append(message.format(line=line))
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
        help="FTP password (omit for anonymous access).",
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

    password = args.password or ""

    destination_root = args.download_dir.resolve()
    destination_root.mkdir(parents=True, exist_ok=True)

    ftp_cls: Type[ftplib.FTP] = ftplib.FTP

    error_log_path = destination_root / "error.log"
    error_entries: List[str] = []

    def _finalize(exit_code: int) -> int:
        if error_entries:
            try:
                error_log_path.write_text("\n\n".join(error_entries) + "\n", encoding="utf-8")
            except OSError as exc:
                print(f"Failed to write error log {error_log_path}: {exc}", file=sys.stderr)
                return 2
            fail_msg = _color("[FAIL]", COLOR_FAIL)
            print(f"{fail_msg} Look here for error log: {error_log_path}", file=sys.stderr)
            return exit_code if exit_code != 0 else 1
        if error_log_path.exists():
            try:
                error_log_path.unlink()
            except OSError:
                pass
        ok_msg = _color("[OK] All PCAP files are valid", COLOR_OK)
        print(ok_msg, file=sys.stderr)
        return 0

    try:
        with ftp_cls() as ftp:
            ftp.connect(args.ftp_host, args.port, timeout=args.timeout)
            ftp.login(args.username, password or "")
            if args.ftp_path and args.ftp_path != "/":
                ftp.cwd(args.ftp_path)

            remote_files = discover_remote_pcaps(
                ftp,
                args.pcap_pattern,
            )
            if not remote_files:
                error_entries.append("No PCAP files found to download.")
                return _finalize(1)

            exit_code = 0
            for remote_file in remote_files:
                local_path = download_remote_file(ftp, remote_file, destination_root)
                result = validate_pcap(tshark_path, local_path)

                status_ok = result.ok and not (args.fail_on_warning and result.warnings)
                status = "OK" if status_ok else "FAIL"
                print(f"[{status}] {remote_file.relative_path}")

                if not status_ok:
                    block_lines: List[str] = [f"File: {remote_file.relative_path}"]
                    if result.warnings:
                        block_lines.append("Warnings:")
                        block_lines.extend(f"  - {warning}" for warning in result.warnings)
                    if result.errors:
                        block_lines.append("Errors:")
                        block_lines.extend(f"  - {err}" for err in result.errors)
                    if not result.errors and not result.warnings:
                        block_lines.append("No additional details available.")
                    error_entries.append("\n".join(block_lines))

                if result.errors:
                    exit_code = max(exit_code, 1)
                elif args.fail_on_warning and result.warnings:
                    exit_code = max(exit_code, 1)
            return _finalize(exit_code)
    except ValidationError as exc:
        error_entries.append(str(exc))
        return _finalize(2)
    except ftplib.all_errors as exc:
        error_entries.append(f"FTP error: {exc}")
        return _finalize(2)


if __name__ == "__main__":
    raise SystemExit(main())
