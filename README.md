# Python Security Configuration Checker

A small Python portfolio project that reviews a **local JSON configuration file** for a handful of common security misconfigurations. It is intended for learning and demonstrating defensive security fundamentals.

## Checks included

- Debug mode enabled
- Wildcard (`*`) CORS origins
- Missing `Secure`, `HttpOnly`, or suitable `SameSite` cookie settings
- Password minimum length below 12 characters
- Rate limiting disabled

## Requirements

- Python 3.10 or newer
- No third-party packages required

## Run the checker

From this project directory, run:

```bash
python checker.py sample_config.json
```

The sample file is intentionally insecure, so the checker should print findings and exit with status code `1`. To test a clean configuration, edit a copy of `sample_config.json` with safer values and run the checker against that file.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Example output

The sample configuration should produce findings for debug mode, wildcard CORS, cookie settings, password length, and rate limiting. Exact formatting may vary by version.

## Limitations

This is a basic static checker, not a complete security audit. It does not inspect application code, contact any server, test a live website, or prove that a system is secure. The checks are simplified examples; production requirements depend on the application and its threat model.

## Suggested next steps

- Add checks for HTTPS-only deployment settings.
- Support JSON output for CI pipelines.
- Add more unit tests for invalid input types.
- Document the intended configuration schema for a sample web application.

## Portfolio note

Before publishing, run the tests, read through the code, and be ready to explain each check and its limitations in an interview.
