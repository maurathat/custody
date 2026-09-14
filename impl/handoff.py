"""The handoff payload class: record derivation, structural validation, chain verification.

Implements SPEC.md sections 2 and 3 over the vendored impl/canon.py, which is used as
shipped. canon.dataset_id() hard-codes the dataset shape and rejects every handoff record,
so this module calls canon's pipeline steps directly and applies the handoff shape itself:

    canon._admit       step 1: strict UTF-8, no BOM, well-formed JSON, no duplicate member
                       names after escape decoding, scalar Unicode, integral numbers within
                       +/-(2**53 - 1)
    canon._fold_nfc    step 2: NFC-fold every string and member name, reject collisions
    canon._identifier  steps 3-4: exclude the top-level address, RFC 8785 JCS, SHA-256 hex

Two readings of SPEC section 3 are settled here; the spec text does not settle them:

  * H2 at a derived hop. As written, H2 compares R.subject with P.subject for every rel,
    H3 compares it with P.result when P is derived, and H1 forces P.result != P.subject,
    so no record could follow a derived one. Here both rules compare R.subject with P's
    outgoing artifact: P.result if P.rel == "derived", else P.subject. When P is derived,
    H2's observed clause is skipped: P.observed digests the previous artifact's bytes, so
    there is no baseline for the new artifact's.
  * Resolution. prev resolves only against addresses recomputed from record content. A
    carried address is excluded from the hash, so it never resolves anything. A prev cycle
    would therefore need a SHA-256 fixpoint; the Cyclic guard keeps the walk total on any
    input, but no constructible record set reaches it.
"""
from __future__ import annotations

import hashlib

import canon

SCHEMA_VERSION = "1"
RELS = ("verbatim", "reencoded", "derived")
REQUIRED = ("subject", "observed", "from", "to", "seq", "rel", "schema_version")
MEMBERS = frozenset(REQUIRED) | {"prev", "result", "address"}
REFERENCE_TYPES = {"subject": "dataset", "observed": "dataset-bytes", "prev": "handoff", "result": "dataset"}

VERIFIED, FAILED, UNRESOLVED, MALFORMED, CYCLIC = "Verified", "Failed", "Unresolved", "Malformed", "Cyclic"


class HandoffError(Exception):
    """A refusal. Every one carries a stable code; nothing here returns a placeholder value."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class AdmissionError(HandoffError):
    """Canonicalization steps 1-2 refused the bytes. The code is canon.py's reason."""


class ShapeError(HandoffError):
    """The payload is outside the closed shape of SPEC section 2."""


class RuleError(HandoffError):
    """A record-local rule of SPEC section 3 fails: H1, or prev absent iff seq == 0."""


def _admit(record: bytes):
    if not isinstance(record, bytes):
        raise TypeError("a handoff record is bytes")
    try:
        return canon._fold_nfc(canon._admit(record))
    except canon.Reject as reject:
        raise AdmissionError(reject.reason) from None


def _check_reference(name: str, ref) -> None:
    if not (isinstance(ref, dict) and set(ref) == canon.REFERENCE_KEYS
            and ref["digest_alg"] == "SHA-256"
            and isinstance(ref["digest"], str) and canon.HEX64.match(ref["digest"])):
        raise ShapeError("MALFORMED_REFERENCE")
    if ref["type"] != REFERENCE_TYPES[name]:
        raise ShapeError("WRONG_REFERENCE_TYPE")


def check_record(record: bytes) -> dict:
    """Admit one record and apply the structural rules; return the folded payload or raise."""
    payload = _admit(record)
    if not isinstance(payload, dict):
        raise ShapeError("NOT_AN_OBJECT")
    if set(payload) - MEMBERS:
        raise ShapeError("UNKNOWN_MEMBER")
    if any(name not in payload for name in REQUIRED):
        raise ShapeError("MISSING_MEMBER")
    for name in REFERENCE_TYPES:
        if name in payload:
            _check_reference(name, payload[name])
    if not all(isinstance(payload[name], str) and payload[name] for name in ("from", "to")):
        raise ShapeError("INVALID_AGENT")
    seq = payload["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise ShapeError("INVALID_SEQ")
    if seq < 0:
        raise ShapeError("SEQ_OUT_OF_RANGE")  # the upper bound is enforced at admission
    if payload["rel"] not in RELS:
        raise ShapeError("INVALID_REL")
    if payload["schema_version"] != SCHEMA_VERSION:
        raise ShapeError("UNSUPPORTED_SCHEMA_VERSION")
    if "address" in payload and not (isinstance(payload["address"], str) and canon.HEX64.match(payload["address"])):
        raise ShapeError("MALFORMED_ADDRESS")

    if payload["rel"] == "derived":
        if "result" not in payload:
            raise RuleError("H1_RESULT_REQUIRED")
        if payload["result"]["digest"] == payload["subject"]["digest"]:
            raise RuleError("H1_RESULT_EQUALS_SUBJECT")
    elif "result" in payload:
        raise RuleError("H1_RESULT_FORBIDDEN")
    if seq == 0 and "prev" in payload:
        raise RuleError("H3_PREV_AT_SEQ_ZERO")
    if seq > 0 and "prev" not in payload:
        raise RuleError("H3_PREV_REQUIRED")
    return payload


def derive_address(record: bytes) -> str:
    """Return the record's 64-hex identifier or raise. Validation precedes exclusion."""
    return canon._identifier(check_record(record))


def _on_cycle(nodes: dict) -> set:
    on_cycle, done = set(), set()
    for start in sorted(nodes):
        path, index, current = [], {}, start
        while current in nodes and current not in done and current not in index:
            index[current] = len(path)
            path.append(current)
            current = nodes[current]["prev"]["digest"] if "prev" in nodes[current] else None
        if current in index:
            on_cycle.update(path[index[current]:])
        done.update(path)
    return on_cycle


def _edge(address: str, record: dict, nodes: dict, cyclic: set):
    if address in cyclic:
        return CYCLIC, ["H4_PREV_CYCLE"]
    parent = nodes.get(record["prev"]["digest"])
    if parent is None:
        return UNRESOLVED, ["H3_PREV_UNRESOLVED"]
    derived = parent["rel"] == "derived"
    same_subject = record["subject"]["digest"] == parent["result" if derived else "subject"]["digest"]
    # Under this reading H2's subject clause and H3's are one predicate. Both codes are
    # reported because the spec states both rules.
    reasons = []
    if not same_subject:
        reasons.append("H2_SUBJECT_CHANGED")
    if not derived:
        same_bytes = record["observed"]["digest"] == parent["observed"]["digest"]
        if record["rel"] == "verbatim" and not same_bytes:
            reasons.append("H2_VERBATIM_BYTES_CHANGED")
        if record["rel"] == "reencoded" and same_bytes:
            reasons.append("H2_REENCODED_BYTES_UNCHANGED")
    if parent["seq"] != record["seq"] - 1:
        reasons.append("H3_SEQ_NOT_CONSECUTIVE")
    if not same_subject:
        reasons.append("H3_SUBJECT_DISCONTINUITY")
    return (FAILED, reasons) if reasons else (VERIFIED, [])


def verify_chain(records) -> dict:
    """Reconstruct the handoff graph of a record set by following prev only (H2-H4).

    The result depends only on the set of records, never on their order: well-formed records
    are keyed by recomputed address, malformed ones by the SHA-256 of their bytes, and both
    are emitted sorted. Each record carrying prev contributes one edge in a SPEC section 3
    state; each malformed record contributes a Malformed entry. The set is verified only if
    every entry is Verified.
    """
    nodes, malformed = {}, {}
    for record in records:
        try:
            payload = check_record(record)
        except HandoffError as error:
            malformed[hashlib.sha256(record).hexdigest()] = error.code
            continue
        payload.pop("address", None)  # excluded from identity, so never part of the graph
        nodes[canon._identifier(payload)] = payload
    cyclic = _on_cycle(nodes)
    edges = []
    for address in sorted(nodes):
        if "prev" in nodes[address]:
            state, reasons = _edge(address, nodes[address], nodes, cyclic)
            edges.append({"record": address, "prev": nodes[address]["prev"]["digest"],
                          "state": state, "reasons": reasons})
    for digest in sorted(malformed):
        edges.append({"record_bytes_sha256": digest, "state": MALFORMED, "reasons": [malformed[digest]]})
    return {"nodes": [{"address": address, "seq": nodes[address]["seq"]} for address in sorted(nodes)],
            "edges": edges,
            "verified": all(edge["state"] == VERIFIED for edge in edges)}
