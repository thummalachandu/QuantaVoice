# v17.2.1 - tests that really run (no skips)

No product code changed except the version string. This release fixes the test suite so a green result is honest.

- `run_tests.py` is strict: any skipped, expected-failure or unexpected-success test makes the run fail. It prints a
  summary line (`ran / passed / failed / errors / skipped`) and `ALL TESTS PASSED, NONE SKIPPED` only when clean.
- Headless Linux: `run_tests.py` starts a virtual display (Xvfb) by itself. Windows and macOS use the desktop session.
- GUI tests (`test_v17_gui`, `test_v17_1_consent_wiring`, `test_v17_2_languages`): a missing display is now a
  **failure with an explanation**, not a silent skip. The `try/except` that silently dropped the GUI test classes if
  the import failed was removed.
- GUI test cleanup uses `addCleanup`, so patches, servers, temp dirs and the Tk root are released even when `setUp`
  fails half-way (ToDo A3). Outage tests that stop the server themselves are still handled.
- Platform skips replaced by real assertions: `test_device_rejects_nonwindows` mocks a non-Windows host so it runs on
  every OS; the TLS 1.0/1.1 test checks the server minimum version when the local OpenSSL cannot offer old TLS; the key
  file permission test checks the file exists everywhere and the POSIX mode bits where they exist.
- `requirements.txt`: `numpy` pinned to 2.5.4 (ToDo A4).
- `APP_VERSION` (CBOM) is 17.2.1.
