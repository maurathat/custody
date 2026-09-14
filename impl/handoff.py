"""The handoff payload class: record derivation, structural validation, chain verification.

Implements SPEC.md sections 2 and 3 over the vendored impl/canon.py, which is used as
shipped. canon.dataset_id() hard-codes the dataset shape and rejects every handoff record,
so this module calls canon's pipeline steps directly and applies the handoff shape itself:

    canon._admit       step 1: strict UTF-8, no BOM, well-formed JSON, no duplicate member
                       names after escape decoding, scalar Unicode, integral numbers within
                       +/-(2**53 - 1)
    canon._fold_nfc    step 2: NFC-fold every string and member name, reject collisions
    canon._identifier  steps 3-4: exclude the top-level address, RFC 8785 JCS, SHA-256 hex

The work splits along the line SPEC.md draws. check_record applies every intra-record
constraint of section 2 (shape, member types, reference form, the rel/result and prev/seq
pairings, result != subject), so whether a record has an address is decided from that record
alone. verify_chain applies the inter-record rules of section 3, which need a predecessor:
resolution, seq - 1 and subject == out(P) (H3), and the observed comparison (H2).
derive_address never consults the carried address; check_address reports whether it agrees,
as a third kind of result that is neither a section 2 refusal nor a section 3 chain state.

One reading is settled here rather than in the spec text:

  * Resolution. prev resolves only against addresses recomputed from record content. A
    carried address is excluded from the hash, so it never resolves anything. A prev cycle
    would therefore need a SHA-256 fixpoint. _on_cycle still walks every prev chain and
    marks any address it revisits as Cyclic, so such a set would be reported rather than
    looped on, but no constructible record set reaches it.
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
ADDRESS_ABSENT, ADDRESS_MATCHES, ADDRESS_DIFFERS = "absent", "matches", "differs"


class HandoffError(Exception):
    """A refusal. Every one carries a stable code; nothing here returns a placeholder value."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class AdmissionError(HandoffError):
    """Canonicalization steps 1-2 refused the bytes. The code is canon.py's reason."""


class ShapeError(HandoffError):
    """The payload is outside the closed shape of SPEC section 2."""


class PairingError(HandoffError):
    """Two members of one record contradict each other (SPEC section 2): rel and result, result
    and subject, or prev and seq."""


def _admit_and_fold(record: bytes):
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
    """Admit one record and apply every intra-record constraint of SPEC section 2; return the
    folded payload or raise. Nothing here needs another record."""
    payload = _admit_and_fold(record)
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
            raise PairingError("RESULT_REQUIRED")
        if payload["result"]["digest"] == payload["subject"]["digest"]:
            raise PairingError("RESULT_EQUALS_SUBJECT")
    elif "result" in payload:
        raise PairingError("RESULT_FORBIDDEN")
    if seq == 0 and "prev" in payload:
        raise PairingError("PREV_AT_SEQ_ZERO")
    if seq > 0 and "prev" not in payload:
        raise PairingError("PREV_REQUIRED")
    return payload


def derive_address(record: bytes) -> str:
    """Return the record's 64-hex identifier or raise. Validation precedes exclusion, and the
    carried address is never consulted."""
    return canon._identifier(check_record(record))


def check_address(record: bytes) -> str:
    """Report whether the carried address agrees with the derived identifier: absent, matches,
    or differs. A record whose carried address differs still derives its address (SPEC
    section 2). Raises only if the record fails section 2, when there is nothing to compare."""
    payload = check_record(record)
    if "address" not in payload:
        return ADDRESS_ABSENT
    return ADDRESS_MATCHES if payload["address"] == canon._identifier(payload) else ADDRESS_DIFFERS


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
    reasons = []
    if not derived:  # base(P) is none after a derived hop, so H2 is not evaluated
        same_bytes = record["observed"]["digest"] == parent["observed"]["digest"]
        if record["rel"] == "verbatim" and not same_bytes:
            reasons.append("H2_VERBATIM_BYTES_CHANGED")
        if record["rel"] == "reencoded" and same_bytes:
            reasons.append("H2_REENCODED_BYTES_UNCHANGED")
    if parent["seq"] != record["seq"] - 1:
        reasons.append("H3_SEQ_NOT_CONSECUTIVE")
    if record["subject"]["digest"] != parent["result" if derived else "subject"]["digest"]:  # out(P)
        reasons.append("H3_SUBJECT_DISCONTINUITY")
    return (FAILED, reasons) if reasons else (VERIFIED, [])


def verify_chain(records) -> dict:
    """Reconstruct the handoff graph of a record set by following prev only (H2-H4).

    The result depends only on the set of records, never on their order: well-formed records
    are keyed by recomputed address, malformed ones by the SHA-256 of their bytes, and both
    are emitted sorted. Each record carrying prev contributes one edge in a SPEC section 3
    state. A malformed record fails section 2, so it has no address, no node and no edge; it
    is listed under malformed, keyed by the SHA-256 of its bytes. The set is verified only if
    nothing is malformed and every edge is Verified.
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
    rejected = [{"record_bytes_sha256": digest, "state": MALFORMED, "reasons": [malformed[digest]]}
                for digest in sorted(malformed)]
    return {"nodes": [{"address": address, "seq": nodes[address]["seq"]} for address in sorted(nodes)],
            "edges": edges,
            "malformed": rejected,
            "verified": not rejected and all(edge["state"] == VERIFIED for edge in edges)}
