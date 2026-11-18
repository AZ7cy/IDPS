# Design: NetSentinel IDPS v5 code repair

## Overview
Make small, local changes to `NetSentinel_IDPS_v5.py`. Do not restructure the code.

The repair fixes findings F1–F5 from `requirements.md`:

- F1, F2: make detector key eviction safe and keep companion counters in sync (R1).
- F3: remove an unused variable (R2).
- F4, F5: fix counter reset and trusted-host normalization (R3).

Features, UI, rule semantics and the database schema stay unchanged (R4).

## Architecture
The existing structure stays as it is. The changes touch three classes:

- `Detector`: per-rule state tables, bounded by `_cap_keys` and cleaned by `_gc`.
  `Detector.inspect` updates the tables for each packet and evaluates the rules.
- `Main`: the application controller. It owns `reset_counters` and `add_trusted`.
- `Store`: database access. It owns `untrust` and the existing `unblock`.

Packet flow inside `Detector.inspect` for capped rules after the fix:

1. Append the new event to the key's deque.
2. Call `_cap_keys` with `keep=<current key>` and, where present, the companion counter table.
3. Evaluate the rule against the updated, bounded state.

Appending before capping (step 1 before step 2) is what prevents a new key from being
evicted as the "oldest" empty entry.

## Components and Interfaces

### `Detector._cap_keys` (F1, F2 → R1)
New signature, backward compatible:

```python
def _cap_keys(self, d, now, cap=5000, keep=None, companions=()):
```

- Return early if `len(d) <= cap` (unchanged).
- Build eviction candidates from all keys except `keep`, sorted by the timestamp of each
  key's newest item. Empty deques sort first.
- Pop `len(d) - cap` victims from `d` and from every dict in `companions`.

`keep` and `companions` are optional keyword parameters, so existing callers keep working (R4.2).

### Call sites in `Detector.inspect`
| Rule | Table | Change |
|------|-------|--------|
| NET-002 | `rate_by_src` | `keep=src` |
| NET-001 | `pair_ports` | append first, then cap with `keep=pk`, `companions=(pair_port_counts,)` |
| NET-003 | `syn_by_dst` | `keep=dst`, `companions=(syn_source_counts,)` |
| NET-004 | `horizontal` | append first, then cap with `keep=src`. `horizontal_counts` is keyed by `(src, port)`; the existing `_gc` already drops entries whose `src` is gone. |
| NET-005 | `stealth_by_src` | `keep=src` |
| ICMP-001 | `icmp` | `keep=src` |

### Minor fixes
- F3 (`Detector.inspect`): delete the `is_synack` assignment.
- F4 (`Main.reset_counters`): use `self._last_error_dialog.clear()` and remove the duplicate
  `dropped_capture` reset.
- F5 (`Main.add_trusted`): validate with `normalize_network` instead of `ipaddress.ip_network`.
- F5 (`Store.untrust`): normalize the key with `normalize_network` (falling back to the raw
  key) before deleting, the same way `unblock` does.

## Data Models
No database schema changes. The in-memory detector tables affected are:

| Table | Key | Value | Companion |
|-------|-----|-------|-----------|
| `rate_by_src` | `src` | deque of events | none |
| `pair_ports` | `pk` (source/destination pair) | deque of events | `pair_port_counts` (same key) |
| `syn_by_dst` | `dst` | deque of events | `syn_source_counts` (same key) |
| `horizontal` | `src` | deque of events | `horizontal_counts`, keyed by `(src, port)`, cleaned by `_gc` |
| `stealth_by_src` | `src` | deque of events | none |
| `icmp` | `src` | deque of events | none |

A companion table passed to `_cap_keys` must use the same key as its primary table.
`horizontal_counts` uses a different key, so it is not passed as a companion; `_gc` handles it.

`Main._last_error_dialog` stays a `defaultdict` for the lifetime of `Main`.

## Correctness Properties

### Property 1: Bounded size
After `_cap_keys(d, ..., cap=N)`, `len(d) <= N`.

**Validates: Requirements 1.1**

### Property 2: Current key survives
If `keep` is in `d` before the call, it is still in `d` after the call, even when PCAP
replay delivers out-of-order timestamps.

**Validates: Requirements 1.1**

### Property 3: LRU eviction
Every evicted key has a newest-item timestamp no later than any surviving key other than
`keep`. Empty deques are evicted first.

**Validates: Requirements 1.1**

### Property 4: Companion sync
For each companion `c`, a key evicted from `d` is also absent from `c`.

**Validates: Requirements 1.2**

### Property 5: No stale alerts
NET-001 alerts only when the unique ports in `pair_ports[pk]` within the rule window reach
the threshold.

**Validates: Requirements 1.3**

### Property 6: Reset type stability
After `reset_counters`, `_last_error_dialog` is a `defaultdict` and each counter is
assigned once.

**Validates: Requirements 3.1**

### Property 7: Normalization symmetry
For any input `x`, `untrust(x)` removes the entry created by `add_trusted(x)`, including
IPv4-mapped IPv6 forms.

**Validates: Requirements 3.2**

## Error Handling
- `_cap_keys` with `keep` not present in `d`: treat as no protected key; evict normally.
- `_cap_keys` with a companion missing a victim key: pop with a default so no `KeyError` is raised.
- `add_trusted` with invalid input: `normalize_network` rejects it, and the existing
  invalid-input path in `add_trusted` reports the error. Nothing is stored.
- `Store.untrust` with input `normalize_network` cannot parse: fall back to the raw key so
  previously stored, non-normalized entries can still be removed.

## Testing Strategy
- **Static analysis (R2.1):** `python -m pyflakes NetSentinel_IDPS_v5.py` reports nothing.
- **Rule regression probe (R4.1):** a headless probe with a temp DB sends traffic for every
  rule and confirms all nine fire (NET-001..005, ICMP-001, WEB-001, DNS-001, IOC-001).
- **Eviction probe (R1.1–R1.3):** fill `pair_ports` past the cap and confirm that the current
  key survives, `pair_port_counts` stays in sync with `pair_ports`, and NET-001 does not fire
  on stale counts.
- **Interface check (R4.2):** confirm the DB schema, rule seeds and public method signatures
  are unchanged, and that the only new parameters are the optional `keep` and `companions`.
