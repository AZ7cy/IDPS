# Requirements: Snort and Suricata rule support

## Introduction
IDPS loads Snort 2.9, Snort 3 and Suricata rule files and matches them in its own
detector, without running Snort or Suricata. Only part of the rule language is supported. Every
rule that cannot be evaluated faithfully is skipped and reported with the reason. The earlier specs
still apply; only GUI and worker code may import PyQt6.

## Requirements

### S1 – Loading
1. The user SHALL be able to load rule files (`.rules` or any text file), folders (all `*.rules` files inside, recursively) and archives (`.tar.gz`, `.tgz`, `.tar`, `.zip`; their `*.rules` members).
2. Blank lines and `#` comments SHALL be ignored. Lines ending in `\` SHALL be joined with the next line.
3. Every other line SHALL either load or be reported as skipped with a reason. The load report SHALL give the number of files, rules seen, rules loaded, a count per skip reason and up to 500 example skipped rules with file and line.
4. A rule whose `gid:sid` was already loaded SHALL be skipped as a duplicate.
5. Loading SHALL NOT block the GUI, and SHALL replace the active rule set only when it finishes.

### S2 – Rule header
1. Actions: `alert`, `drop`, `reject` (and `rejectsrc`, `rejectdst`, `rejectboth`, `sdrop`), `pass`. `reject` and `sdrop` SHALL behave like `drop`.
2. Protocols: `ip`, `tcp` (and `tcp-pkt`, `tcp-stream`), `udp`, `icmp`, and the application protocols `http` (and `http1`), `dns`, `tls`. Snort 3 service headers such as `alert http (...)` SHALL mean `any any -> any any`.
3. Addresses and ports SHALL support `any`, single values, CIDR, port ranges (`a:b`, `a:`, `:b`), lists, nested lists, `!` negation and variables.
4. Variables SHALL default to the Suricata values: `HOME_NET` = `[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,fe80::/10]` plus this computer's public addresses (IPv6 as /64 prefixes, because home connections usually have public IPv6 addresses and Windows rotates temporary ones), `EXTERNAL_NET` = `!$HOME_NET`, the server groups = `$HOME_NET`, and the usual port groups. `HOME_NET` SHALL be configurable, and the load report SHALL show the value used. An unknown variable SHALL skip the rule.
5. Directions `->` and `<>` SHALL be supported.

### S3 – Payload matching
1. `content` (with `|hex|` bytes and escapes, `!` negation), and the modifiers `nocase`, `depth`, `offset`, `distance`, `within`, `startswith`, `endswith`, `fast_pattern`, `rawbytes`. Snort 3 comma suboptions (`content:"x",nocase,depth 4`) SHALL be accepted.
2. `pcre` with flags `i s m x A R`, the buffer flags `U I H D M C K W Z V`, and `B O` (ignored). A pattern Python's `re` cannot compile, or any other flag, SHALL skip the rule.
3. `isdataat` (absolute, `relative`, `!` negation), `dsize`, `bsize`, `urilen`.
4. Buffers, as sticky buffers (Suricata, Snort 3) and as Snort 2 content modifiers: packet payload (`pkt_data`), `http.uri`, `http.uri.raw`, `http.method`, `http.protocol`, `http.request_line`, `http.start`, `http.header`, `http.header.raw`, `http.header_names`, `http.host`, `http.host.raw`, `http.user_agent`, `http.cookie`, `http.accept`, `http.accept_enc`, `http.accept_lang`, `http.connection`, `http.content_len`, `http.content_type`, `http.referer`, `dns.query`, `tls.sni`, and their underscore forms.
5. Transforms: `dotprefix`, `to_lowercase`, `to_uppercase`, `header_lowercase`, `strip_whitespace`, `compress_whitespace`, `url_decode`, `to_md5`, `to_sha1`, `to_sha256`, `strip_pseudo_headers`.
6. HTTP buffers SHALL come from a single packet's request (no stream reassembly). Response-side buffers and request bodies are not supported.

### S4 – Other keywords
1. `flags` (with `+`, `*`, `!` and an ignore mask), `sameip`, `flow` (`established` and `not_established` are checked; direction keywords are accepted because the rule header already sets direction), `flowbits` (`set`, `unset`, `toggle`, `isset`, `isnotset`, `noalert`, with `|` and `&` groups), `noalert`, `threshold` (`limit`, `threshold`, `both`; `by_src`, `by_dst`, `by_rule`, `by_both`, `by_flow`), `detection_filter`.
2. Informational keywords SHALL be read or ignored: `msg`, `sid`, `rev`, `gid`, `classtype`, `priority`, `reference`, `metadata`, `target`, `tag`, `service`, `rem`, `prefilter`, `requires`.
3. Any other keyword SHALL skip the rule with the reason `unsupported keyword "<name>"`.

### S5 – Alerts and prevention
1. Signature matches SHALL be reported as rule `SIG-001`, with the rule's `msg` as title and description, and `[gid:sid:rev] classtype; file:line` as evidence.
2. Severity SHALL come from `priority`, or the classtype's priority: 1 = HIGH, 2 = MEDIUM, 3 and 4 = LOW.
3. SIG-001 on the Detection Rules tab SHALL turn signature matching on and off. Its Window SHALL be the minimum seconds between repeated alerts for one signature, source and destination.
4. The block target SHALL be the source, or the destination when the rule says `target:src_ip`.
5. In the inline IPS, a matching `drop`-type rule SHALL drop the packet, except in dry-run (reported as WOULD_DROP) or when a trusted address is involved. Signature alerts SHALL NOT cause automatic blocklist entries.
6. A matching `pass` rule SHALL suppress signature alerts for that packet.
7. Trusted sources SHALL not be checked, as for the other rules.

### S6 – Performance
1. Rules SHALL be prefiltered by protocol, by an exact-address index for content-less rules with host lists, and by a 4-byte index of each rule's fast pattern, so a packet is only fully checked against rules whose fast pattern occurs in it.
2. At most 4096 bytes of each packet's payload SHALL be inspected.

### S7 – Interfaces
1. GUI: a Signatures tab to add files, folders and archives, remove them, reload, set `HOME_NET`, and see the load report. The choices SHALL be remembered and loaded at startup.
2. Headless: `--rules PATH` (repeatable) and `--home-net`. The load summary SHALL be printed before capture starts. An invalid `--home-net` SHALL exit with code 2.
3. README SHALL list what is supported, how to get the ET Open rules, and the known limits.
