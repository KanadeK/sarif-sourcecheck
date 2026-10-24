# sarif-sourcecheck

Check that **SARIF locations resolve to real source files in your checkout**
before uploading a security report. Catch stale build roots, wrong monorepo
directories, broken artifact indexes, out-of-range lines and indexed SHA-256
mismatches. Offline, read only, Python 3.11+, no runtime dependencies.

A report can be valid JSON and still point every alert at a nonexistent file.
[SARIF Viewer issue 644](https://github.com/microsoft/sarif-vscode-extension/issues/644)
and [CodeQL upload issue 2215](https://github.com/github/codeql-action/issues/2215)
show the practical monorepo problem. This gate checks local evidence; it does
not predict every hosting platform's ingestion behavior.

## Install and run a complete example

In an activated virtual environment:

```console
git clone https://github.com/KanadeK/sarif-sourcecheck.git
cd sarif-sourcecheck
python -m pip install .
sarif-sourcecheck examples/monorepo.sarif --root examples/checkout
sarif-sourcecheck examples/monorepo.sarif --root examples/checkout --base SRCROOT=packages/api --json
```

The first command intentionally exits **1**: the report points to an old build
root. The second exits **0** and resolves `packages/api/app.py`, line 2.
The report and source files stay unchanged. Use `python -m sarif_sourcecheck`
when the console script is outside PATH. Release wheels install with
`python -m pip install PATH_TO_WHEEL`; there is no PyPI release at present.
Uninstall with `python -m pip uninstall sarif-sourcecheck`. No cache is created.

## Monorepos and moved reports

```console
sarif-sourcecheck report.sarif --root . --base %SRCROOT%=packages/api --base BUILDROOT=. --json
```

Quote base IDs when required by your shell (`%` expands in Windows cmd).
Each `--base ID=directory` overrides that `originalUriBaseIds` entry for this
check. The directory must already exist **inside** `--root`. Use forward slashes.
All runs receive the same overrides; check separately if runs need different
mappings for the same ID. Unmapped relative base IDs chain recursively; cycles
and missing IDs fail. Directory bases must end with `/` in the SARIF itself.
Historical absolute roots require an explicit mapping if outside the checkout.
No automatic longest-prefix stripping or basename guessing is performed.

Relative URIs resolve from the checkout, or from their `uriBaseId`. Absolute
`file:///` URIs are allowed only inside the current checkout. URI whitespace must
be percent-encoded. UTF-8 percent decoding occurs once. Network hosts, HTTP
URLs, query strings, fragments, backslashes, NULs, alternate stream syntax and
resolved paths outside the checkout fail. Stable symlinks escaping the checkout
fail too. Compare immutable checkouts: this tool is not a sandbox against another
process replacing filesystem paths while it runs.

## Checks and report

- Physical locations in standard SARIF containers: primary and related locations,
  nested code flows, stacks, graph nodes and run-level thread flow locations.
  Extension `properties` bags and unknown containers are ignored.
- `artifactLocation.index` resolves through `run.artifacts`. If a URI is also
  supplied, both must resolve to the same file.
- Each source must be a readable regular file within the checkout.
- `startLine` / `endLine` must be positive and within UTF-8 source lines.
  CRLF, LF and CR are recognized. A final newline is not an extra source line.
- SHA-256 is verified when an **indexed artifact** declares `hashes["sha-256"]`.
  Other hash algorithms and unindexed hashes are not checked.

Exit **0** means checked locations passed; **1** means a location failed or no
physical locations were found; **2** means malformed input, invalid options or
an operational error. An empty SARIF report is not evidence of source coverage.
Report schema version 1 includes complete counts, failure-code totals and at
most 100 receipts. `--receipt-limit 0` suppresses receipts without skipping work.
`--json` writes machine-readable stdout; diagnostics go to stderr.

Receipts contain JSON pointers, checkout-relative resolved paths and reason
codes. They omit source text, rule messages, original absolute roots and hashes.
Relative filenames themselves may be sensitive. No source files or reports are
uploaded, changed, imported as code or executed.

Default limits: 32 MiB report, 16 MiB per source read. Adjust with
`--max-report-bytes` and `--max-source-bytes`. The JSON document is loaded into
memory; each source is read separately for each checked location. Reports with
many repeated locations may do repeated I/O.

## Scope and alternatives

This is a source-resolution gate, **not a full SARIF schema validator**. It does
not verify column/byte offsets, snippets, fingerprints, rule references, logical
locations, result severity, analysisTarget references, or instrumentation
completeness. Unsupported metadata does not become a successful check.
For broader validation use [SARIF SDK](https://github.com/microsoft/sarif-sdk);
for conversion and summaries use [sarif-tools](https://github.com/microsoft/sarif-tools).
[GitHub's SARIF reference](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
describes hosting-specific requirements. No code from these projects is bundled.

For CI, run this command after the analyzer and before upload, and preserve its
nonzero exit status. It needs only the local report and the analyzed checkout.

## Develop / 中文说明

See [CONTRIBUTING.md](CONTRIBUTING.md). Tests cover source mappings, recursive
base IDs, artifact indexes, URI encodings, symlink containment, source lines,
hash mismatches and malformed input. Clean-wheel acceptance runs both examples
from outside the checkout. CI targets Windows, Linux and macOS.

这是 SARIF 上传前的本地源文件检查工具。它检查路径、monorepo 根目录映射、
文件存在性、行号范围，以及通过 artifact index 引用的 SHA-256。用
`--base ID=相对目录` 显式映射旧 CI 路径；不会改写报告或上传源码。
返回 0 表示已检查的位置通过，1 表示发现问题，2 表示输入或运行错误。
它不替代完整 SARIF schema 校验，也不会证明扫描器发现了所有安全问题。

MIT © KanadeK.
