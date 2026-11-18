# Implementation Plan

## Overview

Repair correctness issues in IDPS: make detector state-cap eviction safe for the active key and its companion dicts, remove dead code, fix counter reset in `Main`, and normalize trusted-host keys. Finish by verifying with pyflakes and headless probes.

## Tasks

- [x] 1. Make `Detector._cap_keys` eviction-safe
  - Add `keep` and `companions` optional parameters; never evict `keep`; evict victims from companion dicts.
  - _Requirements: R1.1, R1.2_

- [x] 2. Fix cap call order and arguments in `Detector.inspect`
  - NET-001 and NET-004: append the event before capping.
  - Pass `keep=` for NET-001/002/003/004/005/ICMP-001 and `companions=` for NET-001/003.
  - _Requirements: R1.1, R1.2, R1.3_

- [x] 3. Remove unused `is_synack` variable
  - _Requirements: R2.1_

- [x] 4. Fix `Main.reset_counters`
  - Clear `_last_error_dialog` in place; remove duplicate `dropped_capture` reset.
  - _Requirements: R3.1_

- [x] 5. Normalize trusted-host add/remove
  - `Main.add_trusted` uses `normalize_network`; `Store.untrust` normalizes its key.
  - _Requirements: R3.2_

- [x] 6. Verify
  - pyflakes clean; headless rule probe (all nine rules fire); eviction probe.
  - _Requirements: R2.1, R4.1, R4.2_

## Notes

- All tasks are complete.
- Task 2 relies on the `keep` and `companions` parameters added in task 1.
- Task 6 runs after all code changes (tasks 1 to 5).

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1", "3", "4", "5"] },
    { "id": 1, "tasks": ["2"] },
    { "id": 2, "tasks": ["6"] }
  ]
}
```
