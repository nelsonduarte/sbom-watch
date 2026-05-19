# sbom-watch

An SBOM operationalizer written in the
[Capa](https://github.com/nelsonduarte/capa-language) language.
Takes a CycloneDX SBOM, a CVE database, and a policy file, and
emits a risk report listing every component that matches a CVE
or violates the policy.

**Why this exists.** In 2026, 48% of security teams admit they
are falling behind on SBOM requirements, and SecurityWeek
reports the problem is not the data, but that SBOMs sit
in a drawer instead of being correlated against vulnerability
feeds and policy. `sbom-watch` is a self-contained, offline,
CI-friendly take on closing that gap: feed it the three inputs,
get a deterministic risk report, and let CI exit non-zero when
the bar isn't met.

It is also a demonstration of [Capa's](https://github.com/nelsonduarte/capa-language)
capability-typed approach in a real-shaped program: the three
matchers, all the rendering, and the severity arithmetic are
**provably pure** in the manifest. Only the parsers and the
two writers ever see an `Fs`, and the `Fs` they see is
attenuated to the directory they were authorised for.

## The problem

Generating an SBOM is the easy part. Operationalising it isn't:

- Match every component against a CVE database (CISA KEV,
  NVD export, OSV.dev, an internal feed).
- Enforce a license policy (no GPL-3.0 in proprietary
  products, LGPL only via dynamic linking, ...).
- Maintain a banned-package list (deprecated internal libs,
  trivial-dependency crates, packages with prior supply-chain
  incidents).
- Surface the result in a way the auditor reads and CI gates.

`sbom-watch` does these four things on three inputs and
produces two outputs.

## Inputs

| File | Format | Purpose |
|------|--------|---------|
| `data/sbom.json` | CycloneDX 1.5 | the software bill of materials |
| `data/cve-db.json` | OSV-style (simplified) | the offline vulnerability feed |
| `data/policy.json` | sbom-watch policy schema | license denylist + banned-package list |

The sample SBOM is a fictional Python application
(`billing-api 2.4.1`) with 10 components. The sample CVE
database hand-codes 5 entries (4 of which match SBOM
components). The sample policy denies GPL-3.0 / AGPL-3.0 /
LGPL-3.0 and bans `internal-legacy-crypto`.

## Outputs

- **`risk-report-DATE.md`** - human-readable markdown report:
  metadata, severity summary, one section per severity with a
  bulleted list of findings.
- **`risk-report-DATE.json`** - the same data structurally,
  consumable by a CI script. Includes a top-level `"failing"`
  boolean that mirrors the exit code logic.

## Run it

Prerequisites: Capa >= 0.8.4 (commit `4c4511b` or newer; the
submodule-resolves-root-siblings loader fix is required).

From the repo root:

```bash
capa --run watch.capa -- data/sbom.json
```

Expected output:

```
[INFO] loading SBOM data/sbom.json
[INFO] loaded 10 component(s)
[INFO] loading CVE database data/cve-db.json
[INFO] loaded 5 CVE entr(ies)
[INFO] loading policy data/policy.json
[INFO] policy: 3 license rule(s), 2 banned package(s)
[WARN] [cve] urllib3@1.26.18 High: urllib3 may leak Cookie header to a redirect target across origin, upgrade to 2.0.7+
[WARN] [cve] pyyaml@5.4.0 Critical: PyYAML FullLoader allows arbitrary code execution via crafted YAML, upgrade to 5.4.1+
[WARN] [cve] werkzeug@2.2.3 High: Werkzeug multipart parser denial of service via crafted form data, upgrade to 3.0.1+
[WARN] [cve] cryptography@41.0.0 Medium: cryptography 41.0.0 mishandles X.509 chain validation under PSS, upgrade to 42.0.0+
[WARN] [license] gnu-readline-stub@0.3.1 Critical: license 'GPL-3.0' on denylist: copyleft incompatible with proprietary product license
[WARN] [license] psycopg2@2.9.5 High: license 'LGPL-3.0' on denylist: LGPL allowed only via dynamic linking - requires architecture review
[WARN] [banned] internal-legacy-crypto@0.1.0 Critical: banned: deprecated; migrate to cryptography>=42.0
[INFO] findings: 3 critical, 3 high, 1 medium, 0 low, 0 info
[INFO] wrote ./risk-report-2026-05-19.md
[INFO] wrote ./risk-report-2026-05-19.json
[WARN] policy gate FAILED: at least one finding >= High
sbom-watch: FAILING
```

### Options

```
Usage: sbom-watch [FLAGS] [OPTIONS] SBOM

Arguments:
  SBOM                       path to a CycloneDX SBOM (must live under data/)

Flags:
  -v, --verbose              enable DEBUG-level logging

Options:
  -c, --cve-db STR           path to OSV-style CVE DB JSON (default: data/cve-db.json)
  -p, --policy STR           path to policy JSON (default: data/policy.json)
  -o, --output-dir STR       directory for report files (default: cwd)
  -f, --fail-threshold STR   exit non-zero when any finding >= this severity
                             (default: read from policy.min_severity_to_fail)
```

Examples:

```bash
# Strict gate: fail on any High or worse.
capa --run watch.capa -- data/sbom.json --fail-threshold High

# Permissive: fail only on Critical.
capa --run watch.capa -- data/sbom.json --fail-threshold Critical

# Different policy.
capa --run watch.capa -- data/sbom.json --policy data/strict-policy.json
```

## The audit story

`capa --manifest watch.capa` shows the capability shape of
every function. The pure / Fs split is the headline:

```
match_cves                  pure
match_licenses              pure
match_banned                pure
run_all                     pure
summarise                   pure
has_failing                 pure
render_markdown             pure
render_json                 pure
parse_sbom                  [Fs]
parse_cve_db                [Fs]
parse_policy                [Fs]
write_text                  [Fs]
run                         [Logger, Fs, Fs]
main                        [Stdio, Fs, Env, Clock]
```

Every matcher and every renderer is provably pure. A diff
that added a stray `stdio.println` inside `match_cves` would
fail to compile because the function does not take a `Stdio`
parameter.

The user-defined `Logger` capability hides `Stdio` past the
`make_stdio_logger` factory: `run` declares `[Logger, Fs, Fs]`,
**not** `[Stdio, Fs, Fs]`. The audit manifest tells a
compliance reviewer exactly which functions can write to disk
and which can speak to a terminal.

### Capability attenuation

`main` acquires a single `Fs` from the runtime and splits it
into two narrower caps:

```capa
let read_fs  = fs.restrict_to("data/")
let write_fs = fs.restrict_to(opts.output_dir)
```

`read_fs` is passed to `parse_sbom`, `parse_cve_db`,
`parse_policy`. `write_fs` is passed to `write_text` (used by
both renderers). Neither half can reach the other's directory;
even a malicious parser that tried to write `/etc/passwd`
would be denied at runtime by `Fs.allows()`.

The audit manifest does not display the attenuation prefixes
(those are runtime data), but the type system shows that no
parser ever sees the write-side `Fs`, and no writer ever sees
the read-side.

## Repo layout

```
.
├── watch.capa            entry point: CLI, attenuated Fs split, orchestration
├── model.capa            shared types: Component, Vulnerability, Policy, RiskFinding, Severity
├── parse.capa            JSON readers: parse_sbom, parse_cve_db, parse_policy
├── matcher.capa          pure matchers: match_cves, match_licenses, match_banned + summarise
├── render.capa           pure renderers: markdown + JSON
├── data/
│   ├── sbom.json         CycloneDX 1.5 fixture (10 components)
│   ├── cve-db.json       OSV-style fixture (5 entries)
│   └── policy.json       license denylist + banned-package list
├── libraries/            vendored Capa seed libraries (capa_cli, capa_datetime, capa_log)
├── LICENSE               MIT
└── README.md
```

## What this exercises in Capa

- **Multi-module project** with a flat root layout and the
  loader's "submodule can import a sibling of the root"
  resolution (a fix that landed in Capa for this kind of
  project).
- **All four built-in caps**: `Fs` (input + output), `Stdio`
  (errors), `Env` (CLI args), `Clock` (report timestamp).
- **User-defined `Logger`** capability via capa_log, with a
  cap-bearing `StdioLogger` impl holding the real `Stdio`.
- **Capability attenuation**: `Fs.restrict_to` splits one
  authority into two narrower ones along read/write lines.
- **Heavy `JsonValue` traversal**: nested objects + arrays in
  three different shapes (CycloneDX, OSV, policy). Exercises
  `as_object` / `as_array` / `as_string` / `as_num` chains
  more than any other demo so far.
- **Sum types** with payloads (`WatchError = JsonError(String) | IoFailed(String) | BadArgs(String) | BadSbom(String)`)
  and without (`Severity = Info | Low | Medium | High | Critical`).
- **The `?` operator** for error propagation through every
  parser and every write.
- **Three seed libraries**, vendored: `capa_cli` for arg
  parsing, `capa_datetime` for ISO 8601 timestamp formatting,
  `capa_log` for levelled logging.

## Limitations

- **Exact-version CVE matching**. OSV's full
  introduced/fixed range semantics are out of scope for v1;
  the demo's `affected_versions` is an explicit list. A v2
  iteration would parse semver ranges and compare numerically
  rather than as strings.
- **First-license-only**. CycloneDX permits a list of
  licenses per component; the parser keeps the first SPDX-
  style entry and ignores the rest.
- **No PURL parsing**. The `purl` string is read but not
  used for matching; ecosystem is matched by name + version
  alone. A v2 would honour ecosystem prefixes
  (`pkg:pypi/...` vs `pkg:npm/...`) so the same name in two
  ecosystems doesn't collide.
- **No VEX intake**. A `notAffected` / `false-positive`
  signal from a VEX document would suppress matching CVEs
  in a real deployment; v1 emits every match.
- **No transitive resolution**. The SBOM is assumed flat (no
  dependency tree walking).
- **TOCTOU race on `Fs.restrict_to`**. The Capa runtime
  canonicalises paths (via `os.path.realpath`) before
  comparing, so `data/../etc/passwd` and symlinks pointing
  outside the prefix are denied. A symlink swap between the
  `allows()` check and the underlying `open()` is still
  possible; closing it requires open-at-dirfd semantics.

## License

MIT. See [LICENSE](./LICENSE).
