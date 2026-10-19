"""Check a local JSON configuration for common security misconfigurations.

This is an educational static checker. It does not scan networks or modify systems.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Finding:
    severity: str
    setting: str
    message: str
    recommendation: str

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.setting}: {self.message}\n"
            f"    Recommendation: {self.recommendation}"
        )


def check_config(config: dict[str, Any]) -> list[Finding]:
    """Return security findings for a configuration dictionary."""
    findings: list[Finding] = []

    if config.get("debug_mode") is True:
        findings.append(Finding(
            "HIGH", "debug_mode", "Debug mode is enabled.",
            "Disable debug mode in production and avoid exposing internal errors."
        ))

    allowed_origins = config.get("cors_allowed_origins", [])
    if isinstance(allowed_origins, list) and "*" in allowed_origins:
        findings.append(Finding(
            "HIGH", "cors_allowed_origins", "CORS allows every origin (*).",
            "List only the trusted origins that need access."
        ))

    cookie_settings = config.get("cookies", {})
    if isinstance(cookie_settings, dict):
        for key, recommendation in (
            ("secure", "Set Secure=true when cookies are used over HTTPS."),
            ("http_only", "Set HttpOnly=true to reduce JavaScript access to session cookies."),
            ("same_site", "Use an appropriate SameSite policy, commonly Lax or Strict."),
        ):
            value = cookie_settings.get(key)
            if key in ("secure", "http_only") and value is not True:
                findings.append(Finding(
                    "MEDIUM", f"cookies.{key}", f"Cookie option {key} is not enabled.",
                    recommendation
                ))
            elif key == "same_site" and str(value).lower() not in {"lax", "strict"}:
                findings.append(Finding(
                    "MEDIUM", "cookies.same_site", "SameSite is missing or not set to Lax/Strict.",
                    recommendation
                ))

    min_length = config.get("minimum_password_length")
    if not isinstance(min_length, int) or isinstance(min_length, bool) or min_length < 12:
        findings.append(Finding(
            "MEDIUM", "minimum_password_length",
            "Minimum password length is missing or below 12 characters.",
            "Set a sensible minimum length and pair it with secure password storage and rate limiting."
        ))

    if config.get("rate_limiting_enabled") is not True:
        findings.append(Finding(
            "MEDIUM", "rate_limiting_enabled", "Rate limiting is not enabled.",
            "Add limits to login and other sensitive endpoints to slow automated abuse."
        ))

    return findings


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError("The JSON root must be an object/dictionary.")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check a JSON config for a few common security settings."
    )
    parser.add_argument("config", type=Path, help="Path to a JSON configuration file")
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Error reading configuration: {exc}")
        return 2

    findings = check_config(config)
    print(f"Configuration: {args.config}")
    if not findings:
        print("No issues detected by this basic checker.")
        print("Note: this does not prove the configuration is secure.")
        return 0

    print(f"Found {len(findings)} potential issue(s):\n")
    for finding in findings:
        print(finding)
    print("\nThis is a basic educational check, not a full security audit.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
