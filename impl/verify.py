"""Check this repository offline and print a pass/fail table.

    python impl/verify.py        # no arguments; exits 1 on any failure

In order: probes of the network guard; every file against vectors/SHA256SUMS; impl/canon.py
against impl/CANON_PROVENANCE; vectors/CROSS_BUILD against the current vectors.json; every vector in vectors/vectors.json; each H4 vector a second time,
byte for byte; the cycle guard; the worked example in example/chain.json; the generated
blocks in README.md and example/README.md. The canon.py check covers its hash, the commit
that README.md and NOTICE quote, and the helpers handoff.py calls.

The network guard is best-effort defence in depth, not a sandbox. Before canon and handoff
are imported it patches Python's socket lookup and send calls so that an accidental network
call fails loudly, and the run probes each patched call. Subprocesses, C extensions and raw
system calls route around it, and the probe list is the patch list, so a call dropped from
both goes unnoticed here; the output pinned in README.md catches it through the row count.
The gate is that verification completes with no network
available. A passing run prints no paths, times, or versions, so every passing run prints
the same bytes, and README.md pins those bytes.
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
import sys
from pathlib import Path


class NetworkUsed(RuntimeError):
    pass


def _refuse(*_args, **_kwargs):
    raise NetworkUsed("verification attempted network access")


GUARDED_FUNCTIONS = ("getaddrinfo", "create_connection", "gethostbyname", "gethostbyname_ex",
                     "gethostbyaddr", "getnameinfo")
GUARDED_METHODS = ("connect", "connect_ex", "sendto", "sendmsg")


def block_network() -> None:
    for name in GUARDED_FUNCTIONS:
        setattr(socket, name, _refuse)
    for name in GUARDED_METHODS:
        setattr(socket.socket, name, _refuse)


if __name__ == "__main__":
    block_network()  # before canon and handoff are imported, so import-time code is covered too

import canon  # noqa: E402
import handoff  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SUMS = ROOT / "vectors" / "SHA256SUMS"
VECTORS = ROOT / "vectors" / "vectors.json"
EXAMPLE = ROOT / "example" / "chain.json"
PROVENANCE = ROOT / "impl" / "CANON_PROVENANCE"
BUILD_ENV = ROOT / "vectors" / "BUILD_ENV"
CROSS_BUILD = ROOT / "vectors" / "CROSS_BUILD"
HASHED_FILES = (".gitattributes", ".gitignore", "LICENSE", "LICENSES.md", "LICENSES/CC-BY-4.0.txt", "NOTICE", "SPEC.md",
                "example/README.md", "example/chain.json", "vectors/BUILD_ENV", "vectors/CROSS_BUILD", "vectors/vectors.json")
PROVENANCE_KEYS = ("source-repository", "source-path", "source-commit", "last-changed-in", "sha256")
QUOTED_COMMIT = re.compile(r"vendored unmodified from\s+(\S+)\s+at commit\s+`?([0-9a-f]{40})`?")
CANON_CALLABLES = ("_admit", "_fold_nfc", "_identifier", "dataset_id")
CANON_VALUES = ("Reject", "REFERENCE_KEYS", "HEX64")
DOC_BLOCKS = (("README.md", "vector-counts"), ("README.md", "cross-build"), ("example/README.md", "example-records"))
TRANSCRIPT = ("README.md", "verify-output")
EXAMPLE_VECTOR = "h3-substitution"



# shared with build_vectors.py ----------------------------------------------------------------
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def coverage() -> list:
    """The files SHA256SUMS must list: every committed file except README.md, whose pinned
    output records this check, and SHA256SUMS itself."""
    impl = sorted(p.name for p in (ROOT / "impl").iterdir() if p.is_file() and not p.name.startswith("."))
    return sorted([f"impl/{name}" for name in impl] + list(HASHED_FILES))


def _fields(path: Path, keys) -> dict:
    fields = {}
    for line in path.read_text().splitlines():
        key, _, value = line.partition(" ")
        if key in keys:
            fields[key] = value.strip()
    return fields


def provenance() -> dict:
    return _fields(PROVENANCE, PROVENANCE_KEYS)


def build_env() -> dict:
    return _fields(BUILD_ENV, ("python", "unicode", "rfc8785"))


def cross_build() -> tuple:
    """(the vectors.json SHA-256 the record was compared against, one dict per rebuild)."""
    compared, rebuilds = None, []
    if CROSS_BUILD.is_file():
        for line in CROSS_BUILD.read_text().splitlines():
            parts = line.split()
            if not parts or line.startswith("#"):
                continue
            if parts[0] == "compared-against":
                compared = parts[1]
            else:
                rebuilds.append(dict(zip(parts[0::2], parts[1::2])))
    return compared, rebuilds


def outcome(raw: bytes) -> dict:
    try:
        return {"address": handoff.derive_address(raw), "carried_address": handoff.check_address(raw)}
    except handoff.HandoffError as error:
        return {"reject": {"error": type(error).__name__, "code": error.code}}


def graph_bytes(graph: dict) -> bytes:
    return json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()


def order_bytes(vector: dict) -> list:
    records = [text.encode() for text in vector["input"]["records"]]
    return [graph_bytes(handoff.verify_chain([records[i] for i in order])) for order in vector["input"]["orders"]]


def evaluate(vector: dict) -> dict:
    """The outcome of one vector, in the form of its expect member."""
    given = vector["input"]
    if "record" in given:
        return outcome(given["record"].encode())
    if "orders" not in given:
        return {"graph": handoff.verify_chain([text.encode() for text in given["records"]])}
    graphs = order_bytes(vector)
    return {"graph": json.loads(graphs[0]), "orders_agree": len(set(graphs)) == 1}


def example_records(example: dict) -> list:
    return [compact(hop["record"]).encode() for hop in example["hops"]]


def abbrev(digest: str) -> str:
    return f"`{digest[:12]}…`"


def render_blocks(doc: dict, example: dict, env: dict, cross: tuple) -> dict:
    vectors = doc["vectors"]
    categories = list(dict.fromkeys(v["category"] for v in vectors))
    lines = ["| category | spec | vectors |", "|---|---|---:|"]
    for category in categories:
        members = [v for v in vectors if v["category"] == category]
        rules = ", ".join(sorted({rule for v in members for rule in v["rule"]}))
        lines.append(f"| {category} | {rules} | {len(members)} |")
    lines.append(f"| **total** | | **{len(vectors)}** |")
    lines += ["", f"Built with CPython {env['python']}, Unicode {env['unicode']}, rfc8785 {env['rfc8785']} "
                  "(recorded in `vectors/BUILD_ENV`)."]
    counts = "\n".join(lines) + "\n"

    payloads = {p["label"]: p for p in example["payloads"]}
    names = {p["dataset_id"]: p["dataset"] for p in example["payloads"]}
    rows = ["| seq | from → to | rel | subject | observed | prev | address |", "|---:|---|---|---|---|---|---|"]
    for hop in example["hops"]:
        r = hop["record"]
        prev = abbrev(r["prev"]["digest"]) if "prev" in r else "—"
        rows.append(f"| {r['seq']} | {r['from']} → {r['to']} | `{r['rel']}` "
                    f"| dataset {names[r['subject']['digest']]} {abbrev(r['subject']['digest'])} "
                    f"| {hop['received']} {abbrev(r['observed']['digest'])} | {prev} | {abbrev(r['address'])} |")
    graph = handoff.verify_chain(example_records(example))
    seqs = {n["address"]: n["seq"] for n in graph["nodes"]}
    rows += ["", "| edge | state | reasons |", "|---|---|---|"]
    for edge in sorted(graph["edges"], key=lambda e: seqs[e["record"]]):
        reasons = ", ".join(f"`{code}`" for code in edge["reasons"]) or "—"
        rows.append(f"| seq {seqs[edge['record']]} → seq {seqs.get(edge['prev'], '?')} | **{edge['state']}** | {reasons} |")
    rows += ["", f"Payloads: " + "; ".join(f"{label} is dataset {p['dataset']}, {len(p['text'].encode())} bytes"
                                            for label, p in payloads.items()) + "."]
    _, rebuilds = cross
    if rebuilds:
        lines = ["`impl/cross_build.py` rebuilt the generated files under other interpreters and compared each "
                 "byte for byte with the committed one (recorded in `vectors/CROSS_BUILD`):", ""]
        lines += [f"- Python {r['python']}, Unicode {r['unicode']}, rfc8785 {r['rfc8785']}: "
                  f"`vectors/vectors.json` {r['vectors.json']}, `example/chain.json` {r['chain.json']}, "
                  f"`vectors/BUILD_ENV` {r['BUILD_ENV']}." for r in rebuilds]
    else:
        lines = ["No rebuild under another interpreter is recorded; run `impl/cross_build.py`."]
    return {"vector-counts": counts, "cross-build": "\n".join(lines) + "\n", "example-records": "\n".join(rows) + "\n"}


def _markers(name: str):
    return f"<!-- generated:{name} (impl/build_vectors.py) -->\n", f"<!-- /generated:{name} -->"


def block(text: str, name: str) -> str:
    begin, end = _markers(name)
    _, found, rest = text.partition(begin)
    body, closed, _ = rest.partition(end)
    if not (found and closed):
        raise ValueError(f"generated block {name} is missing its markers")
    return body


def splice(text: str, name: str, body: str) -> str:
    begin, end = _markers(name)
    head, _, rest = text.partition(begin)
    _, _, tail = rest.partition(end)
    block(text, name)
    return head + begin + body + end + tail


def transcript(report: str) -> str:
    return "```\n" + report + "```\n"


# checks --------------------------------------------------------------------------------------
def _identity(result: dict):
    return result.get("address", result)


def check_vector(vector: dict, by_id: dict):
    got = evaluate(vector)
    if got != vector["expect"]:
        return f"expected {compact(vector['expect'])}, got {compact(got)}"
    if "equivalent_to" in vector and vector["input"] == by_id[vector["equivalent_to"]]["input"]:
        return f"same input as {vector['equivalent_to']}, so the equivalence proves nothing"
    if "equivalent_to" in vector and _identity(got) != _identity(evaluate(by_id[vector["equivalent_to"]])):
        return f"differs from {vector['equivalent_to']}"
    if "differs_from" in vector and _identity(got) == _identity(evaluate(by_id[vector["differs_from"]])):
        return f"does not differ from {vector['differs_from']}"
    return None


def check_example(example: dict, expected_graph: dict) -> list:
    results = []
    for hop in example["hops"]:
        record, payload = hop["record"], next(p for p in example["payloads"] if p["label"] == hop["received"])
        raw = payload["text"].encode()
        name = f"seq {record['seq']}"
        carried = handoff.check_address(compact(record).encode())
        results.append((f"{name} address", None if carried == handoff.ADDRESS_MATCHES else f"carried address {carried}"))
        digests_match = (record["subject"]["digest"] == canon.dataset_id(raw) == payload["dataset_id"]
                         and record["observed"]["digest"] == sha256(raw))
        results.append((f"{name} digests", None if digests_match else "subject or observed does not match its payload"))
    graph = handoff.verify_chain(example_records(example))
    results.append(("graph", None if graph == expected_graph else f"differs from vector {EXAMPLE_VECTOR}"))
    return results


def run_checks():
    rows, failures = [], []

    def row(label: str, results: list) -> None:
        rows.append((label, sum(detail is None for _, detail in results), len(results)))
        failures.extend(f"{label} {name}: {detail}" for name, detail in results if detail is not None)

    results = []
    for owner, names in ((socket, GUARDED_FUNCTIONS), (socket.socket, GUARDED_METHODS)):
        for name in names:
            try:
                getattr(owner, name)(None)
                results.append((name, "the call was allowed"))
            except NetworkUsed:
                results.append((name, None))
            except Exception as error:
                results.append((name, f"not guarded ({type(error).__name__})"))
    row("network guard", results)

    listed = {}
    for line in SUMS.read_text().splitlines():
        digest, _, path = line.partition("  ")
        listed[path] = digest
    results = [("coverage", None if sorted(listed) == coverage() else f"lists {sorted(listed)}, expected {coverage()}")]
    for path in sorted(listed):
        file = ROOT / path
        actual = sha256(file.read_bytes()) if file.is_file() else "missing"
        results.append((path, None if actual == listed[path] else f"sha256 {actual}"))
    row("sha256sums", results)

    pinned = provenance()
    actual = sha256((ROOT / "impl" / "canon.py").read_bytes())
    results = [("sha256", None if actual == pinned["sha256"] else f"sha256 {actual}, pinned {pinned['sha256']}")]
    for path in ("README.md", "NOTICE"):
        quotes = QUOTED_COMMIT.findall((ROOT / path).read_text())
        agrees = (len(quotes) == 1 and pinned["source-repository"] in quotes[0][0]
                  and quotes[0][1] == pinned["source-commit"])
        results.append((f"{path} commit", None if agrees else f"quotes {quotes}, pinned {pinned['source-commit']}"))
    missing = [name for name in CANON_CALLABLES if not callable(getattr(canon, name, None))]
    missing += [name for name in CANON_VALUES if not hasattr(canon, name)]
    results.append(("helpers", None if not missing else f"canon.py lacks {missing}"))
    row("canon.py provenance", results)

    compared, rebuilds = cross_build()
    current = sha256(VECTORS.read_bytes())
    fresh = compared == current and bool(rebuilds)
    row("cross-build record", [("vectors/CROSS_BUILD", None if fresh else
                                 f"compared against vectors.json {compared}, current is {current}; run impl/cross_build.py")])

    doc = json.loads(VECTORS.read_text())
    vectors = doc["vectors"]
    by_id = {v["id"]: v for v in vectors}
    for category in dict.fromkeys(v["category"] for v in vectors):
        row(category, [(v["id"], check_vector(v, by_id)) for v in vectors if v["category"] == category])

    results = []
    for vector in (v for v in vectors if "orders" in v["input"]):
        first, second = order_bytes(vector), order_bytes(vector)
        same = first == second and len(set(first)) == 1
        results.append((vector["id"], None if same else "graph bytes differ between orders or runs"))
    row("H4 repeat run", results)

    ring = {"a": {"prev": {"digest": "b"}}, "b": {"prev": {"digest": "a"}}, "c": {"prev": {"digest": "a"}}, "d": {}}
    found = handoff._on_cycle(ring)
    row("cycle guard", [("two-node ring", None if found == {"a", "b"} else f"found {sorted(found)}")])

    example = json.loads(EXAMPLE.read_text())
    row("example", check_example(example, by_id[EXAMPLE_VECTOR]["expect"]["graph"]))

    rendered = render_blocks(doc, example, build_env(), cross_build())
    results = []
    for path, name in DOC_BLOCKS:
        current = block((ROOT / path).read_text(), name) == rendered[name]
        results.append((f"{path} {name}", None if current else "stale; run impl/build_vectors.py"))
    row("generated docs", results)
    return rows, failures


def render_report(rows: list, failures: list) -> str:
    width = max(len(label) for label, _, _ in rows + [("TOTAL", 0, 0)])
    lines = ["custody verify"]
    for label, passed, total in rows:
        lines.append(f"  {label:<{width}}  {f'{passed}/{total}':>7}")
    passed, total = sum(r[1] for r in rows), sum(r[2] for r in rows)
    lines.append(f"  {'TOTAL':<{width}}  {f'{passed}/{total}':>7}  {'FAIL' if failures else 'PASS'}")
    lines += [f"  FAIL {failure}" for failure in failures]
    return "\n".join(lines) + "\n"


def main() -> int:
    rows, failures = run_checks()
    report = render_report(rows, failures)
    sys.stdout.write(report)
    if failures:
        return 1
    path, name = TRANSCRIPT
    if block((ROOT / path).read_text(), name) != transcript(report):
        sys.stdout.write(f"  FAIL {path} {name} differs from this output; run impl/build_vectors.py\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
