"""Check this repository offline and print a pass/fail table.

    python impl/verify.py        # no arguments; exits 1 on any failure

In order: every file against vectors/SHA256SUMS; impl/canon.py against the hash pinned in
impl/CANON_PROVENANCE; every vector in vectors/vectors.json; each H4 vector a second time,
byte for byte; the cycle guard; the worked example in example/chain.json; the generated
blocks in README.md and example/README.md. Socket connections and name lookups are refused
for the whole run. The output carries no paths, times, or versions, so every passing run
prints the same bytes, and README.md pins those bytes.
"""
from __future__ import annotations

import hashlib
import json
import socket
import sys
from pathlib import Path


class NetworkUsed(RuntimeError):
    pass


def _refuse(*_args, **_kwargs):
    raise NetworkUsed("verification attempted network access")


def block_network() -> None:
    socket.getaddrinfo = socket.create_connection = _refuse
    for name in ("connect", "connect_ex", "sendto"):
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
DOC_BLOCKS = (("README.md", "vector-counts"), ("example/README.md", "example-records"))
TRANSCRIPT = ("README.md", "verify-output")
EXAMPLE_VECTOR = "h3-substitution"



# shared with build_vectors.py ----------------------------------------------------------------
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def coverage() -> list:
    """The files SHA256SUMS must list: everything in impl/, the vectors, the example chain."""
    impl = sorted(p.name for p in (ROOT / "impl").iterdir() if p.is_file() and not p.name.startswith("."))
    return sorted([f"impl/{name}" for name in impl] + ["example/chain.json", "vectors/vectors.json"])


def outcome(raw: bytes) -> dict:
    try:
        return {"address": handoff.derive_address(raw)}
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


def render_blocks(doc: dict, example: dict) -> dict:
    vectors = doc["vectors"]
    categories = list(dict.fromkeys(v["category"] for v in vectors))
    lines = ["| category | spec | vectors |", "|---|---|---:|"]
    for category in categories:
        members = [v for v in vectors if v["category"] == category]
        rules = sorted({token for v in members for token in v["rule"].split() if token.startswith("H")})
        rules = "§3 " + ", ".join(rules) if rules else "§2"
        lines.append(f"| {category} | {rules} | {len(members)} |")
    lines.append(f"| **total** | | **{len(vectors)}** |")
    made = doc["generated_with"]
    lines += ["", f"Generated with CPython {made['python']}, Unicode {made['unicode']}, rfc8785 {made['rfc8785']}."]
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
    return {"vector-counts": counts, "example-records": "\n".join(rows) + "\n"}


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
def check_vector(vector: dict, by_id: dict):
    got = evaluate(vector)
    if got != vector["expect"]:
        return f"expected {compact(vector['expect'])}, got {compact(got)}"
    if "equivalent_to" in vector and vector["input"] == by_id[vector["equivalent_to"]]["input"]:
        return f"same input as {vector['equivalent_to']}, so the equivalence proves nothing"
    if "equivalent_to" in vector and got != evaluate(by_id[vector["equivalent_to"]]):
        return f"differs from {vector['equivalent_to']}"
    if "differs_from" in vector and got == evaluate(by_id[vector["differs_from"]]):
        return f"does not differ from {vector['differs_from']}"
    return None


def check_example(example: dict, expected_graph: dict) -> list:
    results = []
    for hop in example["hops"]:
        record, payload = hop["record"], next(p for p in example["payloads"] if p["label"] == hop["received"])
        raw = payload["text"].encode()
        name = f"seq {record['seq']}"
        derived = handoff.derive_address(compact(record).encode())
        results.append((f"{name} address", None if derived == record["address"] else f"derives {derived}"))
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

    try:
        socket.getaddrinfo("localhost", None)
        refused = "a name lookup was allowed"
    except NetworkUsed:
        refused = None
    row("network guard", [("getaddrinfo", refused)])

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

    pinned = next(line.split()[1] for line in PROVENANCE.read_text().splitlines() if line.startswith("sha256 "))
    actual = sha256((ROOT / "impl" / "canon.py").read_bytes())
    row("canon.py provenance", [("impl/canon.py", None if actual == pinned else f"sha256 {actual}, pinned {pinned}")])

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

    rendered = render_blocks(doc, example)
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
