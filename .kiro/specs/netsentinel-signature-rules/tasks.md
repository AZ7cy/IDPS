# Implementation Plan

- [x] 1. Packet data and models
  - `Packet.data`, `Alert.drop_requested`, payload capture in `parsing.py`, SIG constants and seed.
  - _Requirements: S3.6, S5.1, S6.2_

- [x] 2. Rule parser and compiler
  - `signatures.py`: header, variables, options, buffers, transforms, skip reasons, loading.
  - _Requirements: S1, S2, S3, S4_

- [x] 3. Matcher, prefilter and state
  - Buffers, content/pcre matching, flowbits, thresholds, pass ordering, prefilter index.
  - _Requirements: S3, S4, S6_

- [x] 4. Detector, headless and GUI
  - SIG-001 check and drop handling; `--rules`/`--home-net`; Signatures tab and loader worker.
  - _Requirements: S5, S7.1, S7.2_

- [x] 5. Tests, real rule sets and documentation
  - Tests listed in the design; ET Open coverage and timing; README.
  - _Requirements: S7.3_
