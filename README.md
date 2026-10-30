# ZipScope 1.0.0

Compare a final ZIP's **file inventory** with an independently prepared JSON
allowlist. Standard-library-only, offline Python CLI. Turkish: [README.tr.md](README.tr.md).

Released under the MIT license; see LICENSE. A match means **inventory
matches policy**, not that a ZIP is safe, clean, valid, or suitable for execution.

Source: https://github.com/Muhammet0-1/ZipScope
Download: https://lordms.net/downloads/zipscope-1-0-0.zip

## Quick start

Use Python 3.10 or newer. No package installation is needed. From this directory:

```console
python3 zipscope.py examples/demo-match.zip examples/allowlist.json
python3 zipscope.py examples/demo-findings.zip examples/allowlist.json
python3 zipscope.py examples/demo-findings.zip examples/allowlist.json --json
```

Windows normally uses `py -3` instead of `python3`; Windows and macOS have not
been tested. The bundled ZIPs contain only synthetic placeholders. Their members
are never executed. To recreate them, first move the existing demo ZIPs aside,
then explicitly run `python3 examples/make_demo.py`. That separate helper writes
two fixed archives and refuses to overwrite existing ones; the CLI is read-only.

Expected findings demo (exit 1):

```text
ZipScope: inventory differs from policy
missing: "LICENSE"
unexpected: "debug.log"
```

The example policy is deliberately written before checking the demo ZIP:

```json
{"version":1,"files":["README.md","LICENSE","tool.py"]}
```

Prepare the list from the intended release contents and review it yourself.
There is no command that derives an approved policy from the inspected ZIP.
Wildcards, directory names, exclusion patterns and automatic fixes are absent.

## Contract and output

The two positional arguments explicitly select the ZIP and policy. Nothing is
discovered recursively. Inputs are opened read-only as regular files; Linux input
symlinks and special files are refused. Other operating systems may lack
`O_NOFOLLOW`; their input-symlink behavior has not been verified.

The UTF-8 policy must contain exactly `version` (integer 1, not boolean) and
`files` (1–4096 distinct, nonempty full relative file paths). A UTF-8 BOM,
duplicate object keys, additional keys, malformed JSON and empty policies are
errors. All paths include any top-level archive folder: `release/tool.py` differs
from `tool.py`. Neither whitespace nor path prefixes are stripped.

Comparison uses decoded names, case-sensitive and exact by Unicode code point.
No Unicode normalization, case folding or slash conversion occurs. UTF-8 names
use the ZIP UTF-8 flag; other names use CP437. Visually similar Unicode names can
still be different. Text output quotes names as JSON strings; JSON uses ASCII
escapes. Thus control bytes cannot change terminal formatting. Reports include
member names, which may themselves contain private information. Review reports
before sharing them. Input filesystem paths, comments, file bodies, timestamps
and raw exception messages are not printed.

Valid explicit directory entries ending in `/` are validated and counted but
excluded from the file comparison. Empty directories are not enforced by the
policy. Implicit parents work without explicit entries. Duplicate directory
entries and file/directory collisions are errors. Directory entries declaring
nonzero uncompressed content are unsupported. An empty ZIP reports all policy
files as missing.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Inventory matches the policy |
| 1 | Complete comparison, missing and/or unexpected files |
| 2 | Invalid arguments, unreadable, malformed, unsupported or over-limit input; comparison incomplete |

`--help` and `--version` return 0 without comparison. JSON reports have
`schema_version`, `status` (`match`, `findings`, `error`), sorted `missing` and
`unexpected` arrays, `issues`, and `counts`. An error reports a stable issue code
and optionally an escaped member name; comparison arrays and counts are empty.
The same unchanged inputs and invocation produce the same output. There are no
run timestamps. Output is stdout; shell redirection, if desired, is the caller's
choice and is not performed by ZipScope.

## Deliberately narrow ZIP support

Only single-disk classic ZIP central directories are supported. ZIP64,
encryption, unsupported flags/compression identifiers, self-extracting prefixes,
trailing junk, ambiguous trailers, alternate Unicode-path extra fields, and
legacy extra fields capable of describing Unix links are refused. Recognized
compression IDs are 0, 8, 12 and 14; no decompressor is invoked. A recognized
method does not establish that its compressed stream is valid.

Member paths with absolute roots, colons, backslashes, empty/`.`/`..` components,
control/format/surrogate characters or Unicode line separators are errors.
Trailing dots/spaces and common Windows device components (`NUL`, `CON`, etc.)
are also refused. Unix symlink/special-file metadata is unsupported; symlink
mode bits are refused even with a DOS creator flag. Unknown metadata conventions
cannot be guaranteed to identify every possible link interpretation.

Fixed limits (no override switches): ZIP 64 MiB; central directory 4 MiB; policy
1 MiB; up to 4096 total entries including directories; each name at most 1024
raw bytes and 1024 UTF-8 bytes after decoding. Limits are checked before loading
the central directory. Declared uncompressed size is not a resource allocation:
members are never decompressed. These bounds reduce resource use; they are not
a security proof or a benchmark guarantee.

Only bounded raw tail bytes and central-directory metadata are read. The tail
scan may physically overlap payload bytes while locating the end record; it
does not interpret their contents. Local member headers, compressed data, CRCs,
signatures and local/central consistency are **not validated**. A corrupt payload
or a changed body under an allowed filename can still return 0. Do not modify
inputs during a run; basic file-change detection is not an atomic snapshot.

## What to use alongside it

Git's [archive command](https://git-scm.com/docs/git-archive) creates an archive
from a tree; [export-ignore](https://git-scm.com/docs/gitattributes#_creating_an_archive)
controls exclusions during that process. [Gitleaks](https://github.com/gitleaks/gitleaks)
looks for secrets in content. ZipScope checks the inventory of the resulting
ZIP. It is not an antivirus, secret scanner, integrity/CRC validator, extraction
tool, or proof of release provenance. A password inside an allowed file is
outside its scope. Python's [zipfile documentation](https://docs.python.org/3/library/zipfile.html)
describes the distinct operations for metadata, member reads and extraction.
Sources checked 30 October 2026.

## Verification and release status

Run `python3 -m unittest discover -s tests -v`. Tests use synthetic files only,
including a fake `.env` member; no customer project, real `.env`, personal backup,
network access or shell execution is used by the tool. The test suite creates
temporary ZIPs; the demo helper writes its fixed examples separately.

The release was tested on Linux x86_64 with CPython 3.14.8: 42/42 source tests
and 42/42 tests from the final tool ZIP passed. An independent reviewer also
verified the same suites and 36 CLI cases across source and packaged runtimes.
Windows, macOS and other Python versions have not been tested. These checks are
not an independent security audit or proof that every ZIP variant is supported.

MIT license: see LICENSE. The LICENSE member inside the synthetic demo archives
is a placeholder for the inventory example, not the distribution license.
