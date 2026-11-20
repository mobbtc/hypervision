# Hypervision

Hypervision is a modular Windows scanner for examining system artifacts and identifying evidence of suspicious software activity, process injection, and system changes.

## How it works

1. The scan coordinator selects modules for the configured game profile and runs them through a thread pool.
2. Modules inspect available Windows artifacts, including USN Journal records, Prefetch, event logs, services, drivers, crash dumps, process memory, and measured boot data.
3. YARA rules match file patterns, while native collectors gather context such as timestamps, signatures, file identities, and process information.
4. Structured findings are deduplicated and correlated when their entity identities and timestamps match. Confidence and severity are separate, and contextual indicators do not automatically establish malicious activity.
5. The structured report is written to `%LOCALAPPDATA%\Hypervision\reports\latest.json`. Some existing modules also use the application's logger and network API.

Unavailable telemetry and access restrictions can reduce scan coverage. A missing artifact or a single matching string is not proof of cheating.

## Repository structure

Detection modules are organized directly at the repository root. `detection_root.cpp` coordinates the scan. Shared collectors and structured reporting are in `echo_integration/`, and synthetic test fixtures are in `tests/`.

## Build status

This repository currently contains scanner modules rather than a complete standalone application. Building the full scanner requires the application entry point, `pch.h`, `utils/`, `scan_api/`, a main build configuration, and the required third-party libraries. A complete scanner executable has not been validated.

The standalone component tests require Windows, MSVC with C++17 support, and the Windows SDK. File-pattern tests require Python and `yara-python`.

## Tests

Run the native tests from the repository root:

```bat
tests\run-tests.cmd
```

Adjust the Visual Studio path in that script to match your installation if necessary.

Run the YARA fixtures:

```powershell
python -m pip install yara-python
python tests/test_yara.py
```

The tests use synthetic fixtures and do not run the scanner against personal files. Passing them does not establish detection accuracy across Windows versions or replace clean-system and authorized laboratory testing.

## Source package

[Download the Hypervision source package](output/hypervision-source.zip).
