#!/usr/bin/env python3
"""Example harness that drives validate_pcap.main using a JSON config."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import validate_pcap


CONFIG_PATH = Path(__file__).with_name("validate_pcap_config.json")


def load_config(path: Path = CONFIG_PATH) -> Dict[str, Any]:
    """Load configuration values from a JSON file."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise SystemExit(f"Config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Config file is not valid JSON ({path}): {exc}") from exc

    if not isinstance(data, dict):
        raise SystemExit(f"Config root must be an object; got {type(data).__name__}")
    return data


def _build_args(config: Dict[str, Any]) -> List[str]:
    """Translate config keys into validate_pcap CLI arguments."""
    def _get_required(key: str) -> Any:
        if key not in config:
            raise SystemExit(f"Missing required config key: {key}")
        return config[key]

    args: List[str] = [
        "--ftp-host",
        str(_get_required("ftp_host")),
        "--ftp-path",
        str(config.get("ftp_path", "/")),
        "--username",
        str(config.get("username", "anonymous")),
        "--mount-point",
        str(_get_required("mount_point")),
    ]

    password = config.get("password")
    if password:
        args.extend(["--password", str(password)])

    patterns = config.get("pcap_patterns")
    if patterns:
        if not isinstance(patterns, list):
            raise SystemExit("Config key 'pcap_patterns' must be a list of strings.")
        for pattern in patterns:
            args.extend(["--pcap-pattern", str(pattern)])

    if config.get("recursive", False):
        args.append("--recursive")

    tshark_bin = config.get("tshark_bin")
    if tshark_bin:
        args.extend(["--tshark-bin", str(tshark_bin)])

    curlftpfs_bin = config.get("curlftpfs_bin")
    if curlftpfs_bin:
        args.extend(["--curlftpfs-bin", str(curlftpfs_bin)])

    if config.get("fail_on_warning", False):
        args.append("--fail-on-warning")

    password_env = config.get("password_env")
    if password_env:
        args.extend(["--password-env", str(password_env)])

    return args


def main() -> int:
    """Entry point that forwards constructed args into validate_pcap."""
    config = load_config()
    cli_args = _build_args(config)
    return validate_pcap.main(cli_args)


if __name__ == "__main__":
    raise SystemExit(main())
