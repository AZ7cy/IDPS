# Design: Snort and Suricata rule support

## Overview
A Qt-free module `signatures.py` parses rule text into `Signature` objects, compiles them into an
indexed `RuleSet`, and matches packets. The `Detector` calls `RuleSet.match()` as one more check
(SIG-001). Loading runs on a background thread in the GUI and before capture in headless mode.

## Architecture
```
netsentinel/
  signatures.py  NEW  parser, compiler, RuleSet (prefilter + matcher + flowbits/threshold state), load_paths()
  models.py      CHG  Packet.data (raw L4 payload, not stored); Alert.drop_requested
  parsing.py     CHG  fill Packet.data (first SIG_PAYLOAD_MAX bytes of the TCP/UDP/ICMP payload)
  config.py      CHG  SIG-001 seed, SIG_* constants
  detector.py    CHG  set_signatures(), _check_signatures(), drop handling in process()
  settings.py    CHG  sig_paths, sig_home_net
  workers.py     CHG  SignatureLoadWorker
  gui.py         CHG  Signatures tab
  headless.py    CHG  rules, home_net
  app.py         CHG  --rules, --home-net
```

## Components and Interfaces

### Parsing (`parse_rule(text, variables) -> Signature`, raises `RuleError(reason)`)
1. Header: `action proto src sport dir dst dport (options)`, or the Snort 3 service form `action proto (options)`.
   Address and port expressions are parsed by a small recursive parser into trees of `any`, values,
   lists and negations, after variable substitution. Specs are interned by their resolved text.
2. Options are split on `;` outside quotes, honoring `\` escapes. Each keyword is handled by a table
   entry; unknown keywords raise `RuleError('unsupported keyword "x"')`.
3. Content items carry their buffer. Dotted buffer names are sticky. An underscore name directly after
   a content (Snort 2 style) moves that content to the buffer; otherwise it is sticky (Snort 3 style).
   A rule is treated as Snort 3 when it uses the service header, comma content suboptions or `service:`;
   then underscore names are always sticky.
4. Transforms after a sticky buffer are recorded with it; the buffer key is `(name, transforms)`.

### Matching
- Per packet, a `_Packet` view lazily builds buffers as bytes (payload, HTTP request fields parsed from
  `Packet.data`, `dns.query` and `tls.sni` from `Packet.payload`), their lowercase forms, transformed
  buffers, and cached address/port spec results.
- Content search follows Suricata semantics: `offset`/`depth` are absolute; `distance`/`within` are
  relative to the end of the previous match in the same buffer, with the `within` window starting at
  `prev_end + distance`. A failed relative match backtracks to the next occurrence of earlier contents
  (at most 64 tries per item). Negated contents and `isdataat` do not move the position.
- `pcre` searches the whole buffer, or with `R` the rest of the buffer after the previous match, so `^`
  anchors at the previous match end as in Suricata. `A` anchors at the start of that subject. PCRE spellings
  that Python's `re` writes differently (`(?<name>`, one-digit `\xH`) are rewritten before compiling.
- `isdataat:N` means a byte exists at index N; `isdataat:N,relative` means at least N bytes remain after the
  previous match.
- Options are split on unescaped `;` without tracking quotes, as Snort and Suricata do, because a pcre may
  contain a bare `"`.

### Prefilter
- Rules are grouped by protocol key (`ip`, `tcp`, `udp`, `icmp`, `http`, `dns`, `tls`).
- For each rule with a positive content, the fast pattern is the content marked `fast_pattern`, or the
  longest one. It is indexed under its buffer key by the rarest 4-byte gram of its lowercase bytes
  (gram frequency counted over all fast patterns). Patterns shorter than 4 bytes go into a per-buffer
  "short" list checked with `in`.
- Content-less rules whose source or destination is a positive list of single hosts are indexed by
  address. All other content-less rules are checked on every packet of their protocol.
- Candidates are evaluated in a fixed order: `pass`, then drop-type, then alert; within each, rules that
  set flowbits before rules that test them.

### State
- Flowbits: an `OrderedDict` keyed by a direction-independent 5-tuple, capped at 50,000 flows and
  expired after 600 s of packet time.
- Thresholds and detection filters: windows keyed by `(sid, track value)`, pruned by `RuleSet.prune()`
  from the detector's garbage collection.

### Detector, GUI and headless
- `Detector.set_signatures(rule_set)` swaps the rule set under the detector lock. `reset()` clears its state.
- `_check_signatures` runs after the built-in checks, applies the SIG-001 cooldown per
  `(sid, src, dst)`, and builds alerts as in S5.
- `MainWindow.closeEvent` disconnects the loader, import and feed threads after waiting for them, so a
  result queued just before closing never reaches a closed window. (An exception in a PyQt6 slot aborts the
  process.)
- `process()`: for SIG-001 alerts with `drop_requested`, inline mode sets `WOULD_DROP` in dry-run, or
  `DROP` and drops the packet when no trusted address is involved.
- `SignatureLoadWorker(paths, home_net)` emits `(rule_set, report)`. The GUI shows the report in a
  table of skip reasons and a list of example skipped rules.

## Data Models
- `Packet.data: bytes = b''` (last field). Never stored or shown.
- `Alert.drop_requested: bool = False` (last field). Not stored.
- Rule seed `('SIG-001', 'Snort/Suricata signature match', 'MEDIUM', 1, 1, 60, ...)`.
- Settings: `sig_paths` (list of str), `sig_home_net` (str; `''` means the default).

## Correctness Properties

### Property 1: Every rule line is accounted for
For any rule file, loaded + skipped equals the number of non-blank, non-comment logical lines.

**Validates: Requirements 1.2, 1.3**

### Property 2: Prefilter never hides a match
For any rule set and packet, `RuleSet.match()` returns the same signatures as evaluating every rule
of the packet's protocols without the prefilter.

**Validates: Requirements 6.1**

### Property 3: Content windows
A positive content with `offset o` and `depth d` matches only if the pattern lies entirely inside
`[o, o + d)`. A relative content with `distance x` and `within w` matches only if it lies inside
`[prev_end + x, prev_end + x + w)`.

**Validates: Requirements 3.1**

### Property 4: Negation is complement
For any address or port spec `S` and value `v`, `!S` matches `v` exactly when `S` does not.

**Validates: Requirements 2.3**

### Property 5: Unsupported means skipped
A rule that contains any keyword outside S3 and S4 is never loaded.

**Validates: Requirements 4.3**

### Property 6: Dry-run never drops
In dry-run mode, no signature match causes `process()` to return `drop=True`.

**Validates: Requirements 5.5**

## Error Handling
- Unreadable files and archives are reported in the load report and do not stop other paths loading.
- Parse and compile errors become skip reasons.
- A matching error for one rule (for example a regex runtime error) skips that rule for that packet and
  is counted in `RuleSet.errors`; it never stops packet processing.

## Testing Strategy
- Unit tests for headers, variables, negation, ports, every content modifier, buffers, transforms,
  pcre flags, flags/dsize/bsize/urilen/isdataat, flowbits, thresholds, pass rules, both Snort dialects,
  skip reasons and duplicate SIDs.
- A property-style test compares prefiltered matching with brute-force matching on random packets.
- Loading from a folder and a `.tar.gz`; GUI tab smoke test; headless `--rules` on a PCAP.
- Real data: load the ET Open Suricata 7 and Snort 2.9 rule sets, report coverage, and time matching on
  the PCAP recorded from this machine.
