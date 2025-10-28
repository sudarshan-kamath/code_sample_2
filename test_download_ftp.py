#!/usr/bin/env python3
"""Harness that wires config JSON into validate_pcap_download_ftp."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import validate_pcap_download_ftp


CONFIG_PATH = Path(__file__).with_name("validate_pcap_download_config.json")


def load_config(path: Path = CONFIG_PATH) -> Dict[str, Any]:
    """Read JSON configuration for the downloader."""
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


def build_args(config: Dict[str, Any]) -> List[str]:
    """Translate config keys into CLI-style arguments."""
    def require(key: str) -> Any:
        if key not in config:
            raise SystemExit(f"Missing required config key: {key}")
        return config[key]

    args: List[str] = [
        "--ftp-host",
        str(require("ftp_host")),
        "--ftp-path",
        str(config.get("ftp_path", "/")),
        "--username",
        str(config.get("username", "anonymous")),
        "--download-dir",
        str(require("download_dir")),
    ]

    if "port" in config:
        args.extend(["--port", str(config["port"])])

    password = config.get("password")
    if password:
        args.extend(["--password", str(password)])

    password_env = config.get("password_env")
    if password_env:
        args.extend(["--password-env", str(password_env)])

    if config.get("use_ftps"):
        args.append("--use-ftps")

    patterns = config.get("pcap_patterns")
    if patterns:
        if not isinstance(patterns, list):
            raise SystemExit("Config key 'pcap_patterns' must be a list of strings.")
        for pattern in patterns:
            args.extend(["--pcap-pattern", str(pattern)])

    tshark_bin = config.get("tshark_bin")
    if tshark_bin:
        args.extend(["--tshark-bin", str(tshark_bin)])

    if config.get("fail_on_warning"):
        args.append("--fail-on-warning")

    timeout = config.get("timeout")
    if timeout is not None:
        args.extend(["--timeout", str(timeout)])

    return args


def main() -> int:
    """Load config and invoke the downloader."""
    config = load_config()
    cli_args = build_args(config)
    return validate_pcap_download_ftp.main(cli_args)


if __name__ == "__main__":
    raise SystemExit(main())
