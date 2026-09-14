"""Build vectors/vectors.json, example/chain.json, vectors/SHA256SUMS, and the generated
blocks in README.md and example/README.md. Never hand-edit any of them.

    python impl/build_vectors.py

Every digest that identifies a real record or payload is computed here: subjects with
canon.dataset_id over synthetic dataset bytes, observed digests as SHA-256 of the exact wire
bytes, prev and addresses with handoff.derive_address. Forged references (FORGED_X, FORGED_Y)
are fixed literals by design: their job is to resolve to nothing. Each vector states the
outcome it was written to produce, and the build raises BuildError if the implementation
disagrees. Expected outcomes are then pinned from this implementation: regression and
interoperability targets, not independent evidence.

When vectors.json changes, vectors/CROSS_BUILD goes stale and this build stops after writing
SHA256SUMS. Run impl/cross_build.py with one or more other interpreters, then this again.
"""
from __future__ import annotations

import importlib.metadata
import json
import platform
import unicodedata

import canon
import handoff
import verify
from verify import ROOT, compact, sha256


class BuildError(Exception):
    """A fixture or vector does not do what it was written to do. Raised rather than asserted,
    so python -O cannot remove the check."""


def require(condition: bool, message) -> None:
    if not condition:
        raise BuildError(message)


def ref(kind: str, digest: str) -> dict:
    return {"type": kind, "digest_alg": "SHA-256", "digest": digest}


def swap(text: str, old: str, new: str) -> str:
    require(text.count(old) == 1, f"{old!r} does not occur exactly once")
    return text.replace(old, new)


def edited(text: str, edit) -> str:
    value = json.loads(text)
    edit(value)
    return compact(value)


def reversed_members(value):
    if isinstance(value, dict):
        return {key: reversed_members(item) for key, item in reversed(list(value.items()))}
    return value


def addr(text: str) -> str:
    return handoff.derive_address(text.encode())


def record(seq, frm, to, rel, subject, observed, prev=None, result=None, address=None) -> str:
    fields = {"subject": ref("dataset", subject), "observed": ref("dataset-bytes", observed),
              "from": frm, "to": to, "seq": seq}
    if prev is not None:
        fields["prev"] = ref("handoff", prev)
    fields["rel"] = rel
    if result is not None:
        fields["result"] = ref("dataset", result)
    fields["schema_version"] = handoff.SCHEMA_VERSION
    if address is not None:
        fields["address"] = address
    return compact(fields)


# synthetic wire payloads -----------------------------------------------------------------------
CONTENT = {"sku": "widget", "qty": [1, 2, 3], "label": "Café"}
WIRE_A = compact({"owner": "seller-0", "schema_version": "1", "parents": [], "content": CONTENT})
# The same dataset as a relay might re-emit it: members reordered, indented, integers spelled
# as decimals, and the label in NFD.
WIRE_A_RE = ('{\n  "content": {\n    "label": "Cafe\u0301",\n    "qty": [1.0, 2.0, 3.0],\n'
             '    "sku": "widget"\n  },\n  "owner": "seller-0",\n  "parents": [],\n  "schema_version": "1"\n}\n')
WIRE_B = compact({"owner": "seller-0", "schema_version": "1", "parents": [], "content": {**CONTENT, "qty": [1, 2, 30]}})
DATASET_A, DATASET_B = canon.dataset_id(WIRE_A.encode()), canon.dataset_id(WIRE_B.encode())
WIRE_C = compact({"owner": "buyer-2", "schema_version": "1", "parents": [canon.reference(DATASET_A)],
                  "content": {"sku": "widget", "total": 6}})
DATASET_C = canon.dataset_id(WIRE_C.encode())
OBS_A, OBS_A_RE, OBS_B, OBS_C = (sha256(w.encode()) for w in (WIRE_A, WIRE_A_RE, WIRE_B, WIRE_C))
require(canon.dataset_id(WIRE_A_RE.encode()) == DATASET_A and OBS_A_RE != OBS_A,
        "the re-encoded payload must keep dataset A's identifier and change its bytes")
require(len({DATASET_A, DATASET_B, DATASET_C}) == 3, "datasets A, B and C must be distinct")

# chain fixtures (agents as in SPEC section 5) --------------------------------------------------
R0 = record(0, "seller-0", "buyer-0", "verbatim", DATASET_A, OBS_A)
R1 = record(1, "buyer-0", "buyer-1", "reencoded", DATASET_A, OBS_A_RE, prev=addr(R0))
R2 = record(2, "buyer-1", "buyer-2", "verbatim", DATASET_B, OBS_B, prev=addr(R1))
R2_DERIVED = record(2, "buyer-1", "buyer-2", "derived", DATASET_A, OBS_A_RE, prev=addr(R1), result=DATASET_C)
R3_AFTER = record(3, "buyer-2", "buyer-3", "verbatim", DATASET_C, OBS_C, prev=addr(R2_DERIVED))
R3_STALE = record(3, "buyer-2", "buyer-3", "verbatim", DATASET_A, OBS_A_RE, prev=addr(R2_DERIVED))
R1_VERBATIM = record(1, "buyer-0", "buyer-1", "verbatim", DATASET_A, OBS_A, prev=addr(R0))
R1_VERBATIM_MOVED = record(1, "buyer-0", "buyer-1", "verbatim", DATASET_A, OBS_A_RE, prev=addr(R0))
R1_REENCODED_STILL = record(1, "buyer-0", "buyer-1", "reencoded", DATASET_A, OBS_A, prev=addr(R0))
R1_REENCODED_SWAPPED = record(1, "buyer-0", "buyer-1", "reencoded", DATASET_B, OBS_B, prev=addr(R0))
R2_GAP = record(2, "buyer-0", "buyer-1", "verbatim", DATASET_A, OBS_A, prev=addr(R0))
# Claimed addresses that point at each other. Neither is the address of anything here.
FORGED_X, FORGED_Y = "a1" * 32, "b2" * 32
X = record(1, "buyer-0", "buyer-1", "verbatim", DATASET_A, OBS_A, prev=FORGED_Y, address=FORGED_X)
Y = record(2, "buyer-1", "buyer-2", "verbatim", DATASET_A, OBS_A, prev=FORGED_X, address=FORGED_Y)
MALFORMED = swap(R1, '"seq":1,', '"seq":1,"seq":2,')
MALFORMED_RESPELLED = MALFORMED.replace(",", ", ")  # still two seq members, different bytes
R1_RESPELLED = json.dumps(reversed_members(json.loads(R1)), ensure_ascii=False, indent=2).replace('"seq": 1', '"seq": 1.0')

# canonicalization base: a non-ASCII agent pair exercises NFC -----------------------------------
BASE = record(1, "relé-1", "relé-2", "reencoded", DATASET_A, OBS_A_RE, prev=addr(R0))
BASE_ADDRESS = addr(BASE)
NEAR_MISS = BASE_ADDRESS[:-1] + ("0" if BASE_ADDRESS[-1] != "0" else "1")

ACCEPT = "accept"


def reject(error: str, code: str) -> tuple:
    return (error, code)


def edge(state: str, *reasons: str) -> tuple:
    return (state, reasons)


VERIFIED = edge("Verified")

# (id, category, rule, description, input, intended outcome, relation)
VECTORS = [
    ("canon-base", "canonicalization", "§2", "reference record, compact, fixed member order", BASE, ACCEPT, {}),
    ("canon-member-order", "canonicalization", "§2", "members and reference keys in reverse order",
     compact(reversed_members(json.loads(BASE))), ACCEPT, {"equivalent_to": "canon-base"}),
    ("canon-seq-1.0", "canonicalization", "§2", "seq spelled 1.0", swap(BASE, '"seq":1,', '"seq":1.0,'),
     ACCEPT, {"equivalent_to": "canon-base"}),
    ("canon-seq-1e0", "canonicalization", "§2", "seq spelled 1e0", swap(BASE, '"seq":1,', '"seq":1e0,'),
     ACCEPT, {"equivalent_to": "canon-base"}),
    ("canon-nfd-from", "canonicalization", "§2", "from in NFD",
     swap(BASE, '"from":"relé-1"', '"from":"rele\u0301-1"'), ACCEPT, {"equivalent_to": "canon-base"}),
    ("canon-nfd-to", "canonicalization", "§2", "to in NFD",
     swap(BASE, '"to":"relé-2"', '"to":"rele\u0301-2"'), ACCEPT, {"equivalent_to": "canon-base"}),
    ("canon-escape", "canonicalization", "§2", "from spelled with a \\u escape",
     swap(BASE, '"from":"relé-1"', '"from":"rel\\u00e9-1"'), ACCEPT, {"equivalent_to": "canon-base"}),
    ("canon-indent", "canonicalization", "§2", "two-space indentation and newlines",
     json.dumps(json.loads(BASE), ensure_ascii=False, indent=2), ACCEPT, {"equivalent_to": "canon-base"}),
    ("canon-tabs-crlf", "canonicalization", "§2", "tab indentation and CRLF line ends",
     json.dumps(json.loads(BASE), ensure_ascii=False, indent="\t").replace("\n", "\r\n"), ACCEPT,
     {"equivalent_to": "canon-base"}),
    ("canon-address-correct", "canonicalization", "§2", "carries its own address",
     BASE[:-1] + ',"address":"%s"}' % BASE_ADDRESS, {"carried_address": "matches"}, {"equivalent_to": "canon-base"}),
    ("canon-address-other", "canonicalization", "§2", "carries another record's address",
     BASE[:-1] + ',"address":"%s"}' % addr(R0), {"carried_address": "differs"}, {"equivalent_to": "canon-base"}),
    ("carried-address-differs", "carried-address", "§2",
     "carries its own address with one hex digit changed: derives cleanly, reported as differs",
     BASE[:-1] + ',"address":"%s"}' % NEAR_MISS, {"carried_address": "differs"}, {"equivalent_to": "canon-base"}),

    ("commit-to", "commitment", "§2", "to changed", swap(BASE, '"to":"relé-2"', '"to":"relé-3"'),
     ACCEPT, {"differs_from": "canon-base"}),
    ("commit-seq", "commitment", "§2", "seq changed", swap(BASE, '"seq":1,', '"seq":2,'),
     ACCEPT, {"differs_from": "canon-base"}),
    ("commit-observed", "commitment", "§2", "observed changed",
     edited(BASE, lambda d: d["observed"].update(digest=OBS_A)), ACCEPT, {"differs_from": "canon-base"}),
    ("commit-prev", "commitment", "§2", "prev changed",
     edited(BASE, lambda d: d["prev"].update(digest=addr(R1))), ACCEPT, {"differs_from": "canon-base"}),
    ("commit-rel", "commitment", "§2", "rel changed", swap(BASE, '"rel":"reencoded"', '"rel":"verbatim"'),
     ACCEPT, {"differs_from": "canon-base"}),

    ("adm-duplicate-after-escape", "admission", "§2", "to and t\\u006f: duplicate names after escape decoding",
     swap(BASE, '"to":', '"t\\u006f":"x","to":'), reject("AdmissionError", "DUPLICATE_MEMBER"), {}),
    ("adm-duplicate-address", "admission", "§2", "address twice: validation precedes exclusion",
     BASE[:-1] + ',"address":"%s","address":"%s"}' % (BASE_ADDRESS, BASE_ADDRESS),
     reject("AdmissionError", "DUPLICATE_MEMBER"), {}),
    ("adm-lone-surrogate", "admission", "§2", "from is a lone surrogate",
     swap(BASE, '"from":"relé-1"', '"from":"\\ud800"'), reject("AdmissionError", "NON_SCALAR_UNICODE"), {}),
    ("adm-nfc-name-collision", "admission", "§2", "two member names equal after NFC folding",
     BASE[:-1] + ',"é":1,"e\u0301":2}', reject("AdmissionError", "NFC_NAME_COLLISION"), {}),
    ("adm-seq-fraction", "admission", "§2", "seq 1.5 is not integral", swap(BASE, '"seq":1,', '"seq":1.5,'),
     reject("AdmissionError", "NUMBER_NOT_INTEGRAL"), {}),
    ("adm-seq-2p53", "admission", "§2", "seq 2^53 is outside the integral range",
     swap(BASE, '"seq":1,', '"seq":9007199254740992,'), reject("AdmissionError", "NUMBER_OUT_OF_RANGE"), {}),
    ("adm-seq-2p53-plus-1-decimal", "admission", "§2", "seq 2^53+1 spelled as a decimal",
     swap(BASE, '"seq":1,', '"seq":9007199254740993.0,'), reject("AdmissionError", "NUMBER_OUT_OF_RANGE"), {}),
    ("adm-seq-negative", "admission", "§2", "seq -1", swap(BASE, '"seq":1,', '"seq":-1,'),
     reject("ShapeError", "SEQ_OUT_OF_RANGE"), {}),
    ("adm-seq-boolean", "admission", "§2", "seq true", swap(BASE, '"seq":1,', '"seq":true,'),
     reject("ShapeError", "INVALID_SEQ"), {}),
    ("adm-seq-string", "admission", "§2", "seq \"1\"", swap(BASE, '"seq":1,', '"seq":"1",'),
     reject("ShapeError", "INVALID_SEQ"), {}),
    ("adm-not-object", "admission", "§2", "top-level array", "[]", reject("ShapeError", "NOT_AN_OBJECT"), {}),
    ("adm-unknown-member", "admission", "§2", "unknown top-level member hint", BASE[:-1] + ',"hint":"x"}',
     reject("ShapeError", "UNKNOWN_MEMBER"), {}),
    ("adm-missing-member", "admission", "§2", "observed absent", edited(BASE, lambda d: d.pop("observed")),
     reject("ShapeError", "MISSING_MEMBER"), {}),
    ("adm-ref-extra-key", "admission", "§2", "subject reference carries an extra key",
     edited(BASE, lambda d: d["subject"].update(label="x")), reject("ShapeError", "MALFORMED_REFERENCE"), {}),
    ("adm-ref-missing-alg", "admission", "§2", "subject reference without digest_alg",
     edited(BASE, lambda d: d["subject"].pop("digest_alg")), reject("ShapeError", "MALFORMED_REFERENCE"), {}),
    ("adm-ref-other-alg", "admission", "§2", "digest_alg SHA-512",
     edited(BASE, lambda d: d["subject"].update(digest_alg="SHA-512")), reject("ShapeError", "MALFORMED_REFERENCE"), {}),
    ("adm-hex-uppercase", "admission", "§2", "subject digest in uppercase hex",
     edited(BASE, lambda d: d["subject"].update(digest=DATASET_A.upper())), reject("ShapeError", "MALFORMED_REFERENCE"), {}),
    ("adm-hex-short", "admission", "§2", "subject digest of 63 hex digits",
     edited(BASE, lambda d: d["subject"].update(digest=DATASET_A[:-1])), reject("ShapeError", "MALFORMED_REFERENCE"), {}),
    ("adm-hex-long", "admission", "§2", "subject digest of 65 hex digits",
     edited(BASE, lambda d: d["subject"].update(digest=DATASET_A + "0")), reject("ShapeError", "MALFORMED_REFERENCE"), {}),
    ("adm-subject-wrong-type", "admission", "§2", "subject typed dataset-bytes",
     edited(BASE, lambda d: d["subject"].update(type="dataset-bytes")), reject("ShapeError", "WRONG_REFERENCE_TYPE"), {}),
    ("adm-observed-wrong-type", "admission", "§2", "observed typed dataset: the two digest contexts are not interchangeable",
     edited(BASE, lambda d: d["observed"].update(type="dataset")), reject("ShapeError", "WRONG_REFERENCE_TYPE"), {}),
    ("adm-agent-empty", "admission", "§2", "to is empty", swap(BASE, '"to":"relé-2"', '"to":""'),
     reject("ShapeError", "INVALID_AGENT"), {}),
    ("adm-rel-unknown", "admission", "§2", "rel copied", swap(BASE, '"rel":"reencoded"', '"rel":"copied"'),
     reject("ShapeError", "INVALID_REL"), {}),
    ("adm-schema-version", "admission", "§2", "schema_version 2", swap(BASE, f'"schema_version":"{handoff.SCHEMA_VERSION}"', '"schema_version":"2"'),
     reject("ShapeError", "UNSUPPORTED_SCHEMA_VERSION"), {}),
    ("adm-address-malformed", "admission", "§2", "carried address is not 64-hex", BASE[:-1] + ',"address":"nothex"}',
     reject("ShapeError", "MALFORMED_ADDRESS"), {}),
    ("adm-address-uppercase", "admission", "§2", "carried address in uppercase hex",
     BASE[:-1] + ',"address":"%s"}' % BASE_ADDRESS.upper(), reject("ShapeError", "MALFORMED_ADDRESS"), {}),
    ("adm-address-not-hex", "admission", "§2", "carried address of 64 characters that are not hex",
     BASE[:-1] + ',"address":"%s"}' % ("g" * 64), reject("ShapeError", "MALFORMED_ADDRESS"), {}),

    ("h1-derived", "H1", "§2 (H1)", "derived with a result distinct from subject", R2_DERIVED, ACCEPT, {}),
    ("h1-derived-without-result", "H1", "§2 (H1)", "derived with result absent",
     edited(R2_DERIVED, lambda d: d.pop("result")), reject("PairingError", "RESULT_REQUIRED"), {}),
    ("h1-derived-result-is-subject", "H1", "§2 (H1)", "derived with result.digest == subject.digest",
     edited(R2_DERIVED, lambda d: d["result"].update(digest=DATASET_A)), reject("PairingError", "RESULT_EQUALS_SUBJECT"), {}),
    ("h1-verbatim-with-result", "H1", "§2 (H1)", "verbatim with result present",
     edited(R2_DERIVED, lambda d: d.update(rel="verbatim")), reject("PairingError", "RESULT_FORBIDDEN"), {}),
    ("h1-reencoded-with-result", "H1", "§2 (H1)", "reencoded with result present",
     edited(R2_DERIVED, lambda d: d.update(rel="reencoded")), reject("PairingError", "RESULT_FORBIDDEN"), {}),

    ("h2-verbatim", "H2", "§3 H2", "verbatim: same subject, same observed", [R0, R1_VERBATIM], [VERIFIED], {}),
    ("h2-reencoded", "H2", "§3 H2", "reencoded, the benign case: same subject, observed moved", [R0, R1], [VERIFIED], {}),
    ("h2-verbatim-bytes-moved", "H2", "§3 H2", "verbatim while observed differs from the predecessor's",
     [R0, R1_VERBATIM_MOVED], [edge("Failed", "H2_VERBATIM_BYTES_CHANGED")], {}),
    ("h2-reencoded-bytes-still", "H2", "§3 H2", "reencoded while observed matches the predecessor's",
     [R0, R1_REENCODED_STILL], [edge("Failed", "H2_REENCODED_BYTES_UNCHANGED")], {}),
    ("h2-reencoded-subject-changed", "H2", "§3 H3", "reencoded with a changed subject",
     [R0, R1_REENCODED_SWAPPED], [edge("Failed", "H3_SUBJECT_DISCONTINUITY")], {}),

    ("h3-seq0-with-prev", "H3", "§2 (H3)", "seq 0 carrying prev",
     edited(R0, lambda d: d.update(prev=ref("handoff", addr(R1)))), reject("PairingError", "PREV_AT_SEQ_ZERO"), {}),
    ("h3-seq1-without-prev", "H3", "§2 (H3)", "seq 1 with prev absent", edited(R1, lambda d: d.pop("prev")),
     reject("PairingError", "PREV_REQUIRED"), {}),
    ("h3-seq-gap", "H3", "§3 H3", "seq 2 whose prev is seq 0: a silent drop",
     [R0, R2_GAP], [edge("Failed", "H3_SEQ_NOT_CONSECUTIVE")], {}),
    ("h3-prev-unresolved", "H3", "§3 H3", "prev names a record not in the set", [R1],
     [edge("Unresolved", "H3_PREV_UNRESOLVED")], {}),
    ("h3-substitution", "H3", "§3 H3", "subject changes with no bridging derived record: the substitution",
     [R0, R1, R2], [VERIFIED, edge("Failed", "H2_VERBATIM_BYTES_CHANGED", "H3_SUBJECT_DISCONTINUITY")], {}),
    ("h3-derived-crossing", "H3", "§3 H2, §3 H3", "valid chain crossing a derived record; the next record carries result",
     [R0, R1, R2_DERIVED, R3_AFTER], [VERIFIED, VERIFIED, VERIFIED], {}),
    ("h3-derived-not-followed", "H3", "§3 H3", "after a derived record, the next record keeps the old subject",
     [R0, R1, R2_DERIVED, R3_STALE], [VERIFIED, VERIFIED, edge("Failed", "H3_SUBJECT_DISCONTINUITY")], {}),
    ("h3-forged-cycle", "H3", "§3 H3, §3 H4", "carried addresses forge a prev cycle; prev resolves by recomputed address, so neither resolves",
     [X, Y], [edge("Unresolved", "H3_PREV_UNRESOLVED"), edge("Unresolved", "H3_PREV_UNRESOLVED")], {}),
    ("h3-malformed-member", "H3", "§3 H3", "a record with a duplicate seq member inside a set",
     [R0, MALFORMED], [edge("Malformed", "DUPLICATE_MEMBER")], {}),

    ("h4-two-orders", "H4", "§3 H4", "one record set in forward and reverse array order",
     ([R0, R1, R2, X, MALFORMED], [[0, 1, 2, 3, 4], [4, 3, 2, 1, 0]]),
     [VERIFIED, edge("Failed", "H2_VERBATIM_BYTES_CHANGED", "H3_SUBJECT_DISCONTINUITY"),
      edge("Unresolved", "H3_PREV_UNRESOLVED"), edge("Malformed", "DUPLICATE_MEMBER")], {}),
    ("h4-respelled-record", "H4", "§3 H4", "one record in two spellings, in forward and reverse array order",
     ([R0, R1, R1_RESPELLED], [[0, 1, 2], [2, 1, 0]]), [VERIFIED], {}),
    ("h4-respelled-malformed", "H4", "§3 H4",
     "one malformed record in two spellings: two entries, since it has no canonical form",
     ([R0, MALFORMED, MALFORMED_RESPELLED], [[0, 1, 2], [2, 1, 0]]),
     [edge("Malformed", "DUPLICATE_MEMBER"), edge("Malformed", "DUPLICATE_MEMBER")], {}),
]


def build_vector(vid, category, rule, description, given, intended, relation) -> dict:
    vector = {"id": vid, "category": category, "rule": rule.split(", "), "description": description}
    if isinstance(given, str):
        vector["input"] = {"record": given}
    elif isinstance(given, list):
        vector["input"] = {"records": given}
    else:
        vector["input"] = {"records": given[0], "orders": given[1]}
    got = verify.evaluate(vector)
    if intended == ACCEPT:
        require("address" in got, (vid, got))
    elif isinstance(intended, dict):
        require("address" in got and got.get("carried_address") == intended["carried_address"], (vid, got))
    elif isinstance(intended, tuple):
        require(got.get("reject") == {"error": intended[0], "code": intended[1]}, (vid, got))
    else:
        entries = got["graph"]["edges"] + got["graph"]["malformed"]
        states = sorted((e["state"], tuple(e["reasons"])) for e in entries)
        require(states == sorted(intended), (vid, states))
        require(got.get("orders_agree", True), vid)
    return {**vector, "expect": got, **relation}


def build_example() -> dict:
    payloads = [("wire-0", "A", "dataset A as seller-0 sent it", WIRE_A),
                ("wire-1", "A", "dataset A as buyer-0 re-encoded it", WIRE_A_RE),
                ("wire-2", "B", "dataset B, which buyer-1 sent in place of A", WIRE_B)]
    hops = []
    for (label, *_), text in zip(payloads, (R0, R1, R2)):
        hops.append({"received": label, "record": {**json.loads(text), "address": addr(text)}})
    return {"description": "SPEC section 5 with computed digests. Each hop pairs a record with the exact "
                           "payload its receiver got. Generated by impl/build_vectors.py.",
            "payloads": [{"label": label, "dataset": name, "note": note, "text": text,
                          "dataset_id": canon.dataset_id(text.encode()), "bytes_sha256": sha256(text.encode())}
                         for label, name, note, text in payloads],
            "hops": hops}


def write_json(path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=True, indent=1) + "\n")


def generate() -> tuple:
    """Write the generated data files: vectors.json, example/chain.json and BUILD_ENV.
    impl/cross_build.py calls this alone, under other interpreters."""
    verify.block_network()
    doc = {"class": "handoff",
           "spec": "SPEC.md section 2 (intra-record: shape, pairings, canonicalization) and section 3 (inter-record: H2-H4)",
           "generator": "impl/build_vectors.py",
           "input_encoding": "each record is the UTF-8 encoding of its string",
           "provenance": "Expected outcomes are pinned from this implementation. They are regression and "
                         "interoperability targets, not independent evidence.",
           "vectors": [build_vector(*v) for v in VECTORS]}
    require(len({v["id"] for v in doc["vectors"]}) == len(doc["vectors"]), "vector ids must be unique")
    env = {"python": platform.python_version(), "unicode": unicodedata.unidata_version,
           "rfc8785": importlib.metadata.version("rfc8785")}
    example = build_example()
    write_json(ROOT / "vectors" / "vectors.json", doc)
    write_json(ROOT / "example" / "chain.json", example)
    (ROOT / "vectors" / "BUILD_ENV").write_text(
        "# Environment of the last impl/build_vectors.py run, recorded for reproduction.\n"
        "# vectors.json does not depend on it.\n" + "".join(f"{key} {value}\n" for key, value in env.items()))
    return doc, example, env


def main() -> None:
    doc, example, env = generate()
    for path, name in verify.DOC_BLOCKS:
        file = ROOT / path
        file.write_text(verify.splice(file.read_text(), name, verify.render_blocks(doc, example, env, verify.cross_build())[name]))
    (ROOT / "vectors" / "SHA256SUMS").write_text(
        "".join(f"{sha256((ROOT / p).read_bytes())}  {p}\n" for p in verify.coverage() if (ROOT / p).is_file()))

    rows, failures = verify.run_checks()
    require(not failures, failures)
    path, name = verify.TRANSCRIPT
    file = ROOT / path
    file.write_text(verify.splice(file.read_text(), name, verify.transcript(verify.render_report(rows, failures))))


if __name__ == "__main__":
    main()
