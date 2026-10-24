# Security

Only the latest release is supported. For a vulnerability, use
[GitHub private vulnerability reporting](https://github.com/KanadeK/sarif-sourcecheck/security/advisories/new).
If private reporting is unavailable, open an issue asking the maintainer for
a private channel without disclosing exploit details or attaching sensitive data.

Inputs are untrusted. Run this tool with ordinary user permissions on explicit
input paths. Reports may contain filenames and metadata; review before sharing.
There is no telemetry or network access at runtime. Test fixtures are synthetic.
See README for format boundaries and resource limits.
