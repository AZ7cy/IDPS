# Security policy

## Reporting a vulnerability

Please do not report security problems in public issues. Report them privately, either:
- by email to [puja280106@gmail.com](mailto:puja280106@gmail.com), with "IDPS security" in the subject; or
- through GitHub: [Report a vulnerability](https://github.com/AZ7cy/IDPS/security/advisories/new)
  (or **Security > Report a vulnerability** on the repository page).

Include what you found, how to reproduce it (a rule, a packet capture or a command line helps), and the
version (`python -m netsentinel --version` or `netsentinel/__init__.py`). You should get a first reply within
7 days. Once a fix is released, the advisory is published with credit to you unless you prefer otherwise.

## Supported versions

Only the latest release on the `main` branch gets security fixes.

## Scope

In scope: anything that lets crafted traffic, rule files, blocklist feeds or downloads crash IDPS,
stall detection, evade a loaded rule, block addresses it should not, or read or change files it should not.

Known limitations that are documented in the README (for example no TCP stream reassembly, and the 4 KB
signature payload cap) are not vulnerabilities by themselves, but reports of practical evasions are welcome.
