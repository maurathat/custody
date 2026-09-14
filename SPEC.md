# The `handoff` payload class — draft v0.1

> **Status:** draft v0.1, not a standards-track document.

*Companion payload class to `dataset`. Same canonicalization pipeline, same digest-context discipline, separate artifact type. Scoped for a 4-page paper: one payload class, one consistency rule set, one worked example.*

---

## 1\. Why a second class rather than fields on `dataset`

A `dataset` payload describes an artifact. A `handoff` payload describes an **event**: this artifact passed from A to B at this position in a sequence. Different subject, different issuer, different cardinality — one dataset has N handoff records, signed by N different parties, none of whom need be the owner.

Putting hop fields inside `dataset` fails either way. Include them in the canonical bytes and the identifier moves on every hop, destroying the property the canonicalization exists to provide. Exclude them and nothing commits to them, so a forged hop history is free. The exclusion set ends up doing the work of a second record type, badly.

Two classes sharing one canonicalization is the CPB idiom and is already in use here: `dataset` and `dataset-fingerprint` have separate declared digest contexts, and CPB forbids comparing digests across contexts. `handoff` is a third type in the same family, citing `dataset` by typed digest reference exactly as a child cites a parent.

---

## 2\. Payload shape (closed)

| Member | Type | Notes |
| :---- | :---- | :---- |
| `subject` | typed digest reference, `type: "dataset"` | the artifact that moved |
| `observed` | typed digest reference, `type: "dataset-bytes"` | digest of the wire payload **as received**; distinct digest context, never comparable with `subject` |
| `from` | non-empty string | sender agent identifier |
| `to` | non-empty string | receiver agent identifier |
| `seq` | integral number, `>= 0`, within ±(2⁵³−1) | position in the handoff chain; counts hops, not artifacts |
| `prev` | typed digest reference, `type: "handoff"` | absent **iff** `seq == 0` |
| `rel` | `"verbatim"` | `"reencoded"` | `"derived"` | relation to the predecessor |
| `result` | typed digest reference, `type: "dataset"` | present **iff** `rel == "derived"`, and then `result.digest != subject.digest` |
| `schema_version` | `"1"` |  |
| `address` | string, 64 lowercase hex | carries the identifier; **excluded** before hashing |

Typed digest references are closed objects carrying exactly `type`, `digest_alg: "SHA-256"`, and a 64-hex `digest`, as in the `dataset` class. References live only in the payload, never in a `cpb-refs` header, and are not excluded — so a record commits to its subject, its predecessor, and its result.

**There is no timestamp member.** Order comes from `seq` and `prev`. This is deliberate: producer clocks order nothing, and omitting the field removes the temptation to use it.

**Every constraint in this section is intra-record.** Each is decided from the record alone, before an address exists, so whether a record is addressable never depends on which other records are held. The conditional notes in the table (`prev`, `result`) are part of the shape, not consistency rules. A record that fails any constraint here has no address. §3 holds only the rules that need a predecessor.

**The carried `address`.** `address` carries the derived identifier. It is excluded before hashing, so its value never changes the identifier, and a well-formed value that disagrees does not affect addressability: the record still derives its address. Agreement is reported separately, as its own state (`absent`, `matches`, or `differs`), which is neither a §2 failure nor a §3 chain state.

### Canonicalization

Unchanged from the `dataset` class — the point of a shared serializer:

1. **Admit and validate** — strict UTF-8, no BOM, well-formed JSON, no duplicate member names after escape decoding, no non-scalar Unicode, every number token mathematically integral and in range.  
2. **Transform** — NFC-fold every string and member name, reject names colliding after folding, enforce the closed shape above, normalize reference objects.  
3. **Exclude** the top-level `address`.  
4. **Apply** RFC 8785 JCS, SHA-256, lowercase hex.

Validation precedes exclusion, so an excluded field cannot hide malformed input.

---

## 3\. Consistency rules

This section holds the inter-record rules. **H3 answers whether a record continues the chain; H2 answers whether its declared relation is honest.** H4 fixes how the chain is reconstructed, and H1 is kept only as a pointer to §2.

The vectors in [`vectors/vectors.json`](vectors/vectors.json) check these rules; each vector names the rule it exercises.

Every rule here relates a record to its predecessor and assumes both already have a derived address (§2). For a record with predecessor P, let `out(P)` be the artifact P hands on: `P.result` if `P.rel == "derived"`, otherwise `P.subject`. Let `base(P)` be the last observation of `out(P)`: `P.observed` if `P.rel != "derived"`, and none otherwise, because no party has yet observed a `result` (see §6).

**H1 — relation/result coupling.** Intra-record, so stated once, in the `result` row of §2. The label is kept so that vector identifiers stay stable.

**H2 — relation is verified, not asserted.** Against the predecessor record P:

- `verbatim` requires `observed.digest == base(P).digest`.  
- `reencoded` requires `observed.digest != base(P).digest`.  
- `derived` places no requirement on `observed`.

Where `base(P)` is none, the `observed` requirements are not evaluated. A record whose declared `rel` contradicts its digests is **Failed**, not merely inconsistent.

**H3 — chain integrity.** `prev` MUST resolve to a record P in the set with `P.seq == seq - 1` and `subject.digest == out(P).digest`. Whether `prev` is present at all is intra-record: see the `prev` row of §2.

**H4 — reconstruction determinism.** The handoff graph is computed **only** by following `prev`. No ordering heuristic, no timestamp tiebreak, no agent-interleaving assumption. Normatively:

> Any two conformant analyzers MUST recover the same handoff graph from the same record set.

A record set is a set of byte strings. Records that derive the same address are one node, whatever their spelling. A *Malformed* record has no canonical form, so it is identified by its exact bytes: two spellings of one unparseable record are two entries.

Edges report one of the CPB reference states *Verified*, *Failed* or *Unresolved*, or the profile state *Cyclic*, since under honest content addressing a revisited node signals a forged reference. *Failed* means an addressed record violates H2 or H3. CPB's *Malformed* is a record state here, not an edge state: a record that fails §2, including one with a malformed reference, has no address, so it is not a node and there is nothing to attach an edge to. It is identified by the SHA-256 of its bytes. Only *Verified* counts as a pass.

**Per-edge states are local.** A record that correctly continues the chain from a Failed predecessor has correctly continued it, and reports Verified; conflating the two would let one bad record poison every downstream diagnostic. The verdict for a record set is the composition of its edge states: a set containing any *Malformed* record or any non-Verified edge fails as a whole.

**Carried addresses do not enter the verdict.** Agreement between a record's carried `address` and its derived identifier is reported per record (§2), not in the handoff graph, and does not enter the verdict, because addressability cannot depend on an excluded field. The graph could not hold it in any case: it is keyed by derived address, so spellings of one record that carry different addresses are one node. A set in which every record carries a wrong `address` verifies if its edges do.

### Signing

COSE\_Sign1 in full-content mode. **The recorder is the receiving party** — only the receiver can attest to `observed`. `iss` is the recorder, `sub` the derived record identifier. A recorder differing from `to` is rejected. Records register as SCITT Signed Statements like any other; replay is caught by registration position, not by content.

---

## 4\. Faults this makes visible

| Fault | Signature in the record set |
| :---- | :---- |
| Re-encoded in transit | `subject` stable, `observed` moves, `rel: "reencoded"` |
| Silent substitution | `subject` changes with no bridging `derived` record |
| Silent drop | `seq` gap |
| Forged chain | `prev` *Unresolved*, or *Cyclic* |
| Replay | record already at a log position |

---

## 5\. Worked example (paper-sized)

Three records, one artifact, one substitution caught. Digests abbreviated.

seq 0   from seller-0  to buyer-0

        subject  dataset:965293f8…    observed  bytes:41c9…

        prev     —                     rel  verbatim

seq 1   from buyer-0   to buyer-1

        subject  dataset:965293f8…    observed  bytes:7e02…

        prev     handoff:b31f…         rel  reencoded     ✓ H2 holds

seq 2   from buyer-1   to buyer-2

        subject  dataset:6332808b…    observed  bytes:9ac4…

        prev     handoff:c088…         rel  verbatim      ✗ H3 Failed

Record 2 declares `verbatim` while its `subject` differs from its predecessor's and no `derived` record bridges them: a substitution, detected from the records alone, offline, without an API key. Record 1 shows the benign case the same machinery distinguishes — the bytes changed, the artifact did not.

---

## 6\. Open, and deliberately so

- Whether the recorder is the runtime or the receiving agent in a deployment where the runtime is untrusted.  
- Whether `derived` needs a transform descriptor or whether the `result` dataset's own `parents` set already carries it — probably the latter, which would be a simplification.  
- `seq` is per chain, not per subject: it counts hops, not artifacts, so it continues across a `derived` hop even though the subject changes. Concurrent forks of one artifact are out of scope for v0.1 and should be named as such.  
- The observation gap after a `derived` hop. No party observes `result` before the next hop, so `base(P)` is none, H2's `observed` requirements are not evaluated, and the `rel` of that next hop is unverifiable. Two resolutions: forbid `verbatim` and `reencoded` immediately after a `derived` predecessor and require a fresh origin state; or have the deriving party record its own observation of `result`, so the next hop has a baseline. The second is recommended. Under the first, the observation made after a derivation is never checked, yet it becomes `base(P)` for every later hop, so the gap propagates down the chain instead of closing.  
- Whether a conformance profile should be able to require carried-address agreement. This profile reports disagreement and does not act on it (§2, §3). A deployment might reasonably want to refuse such records, and the spec leaves room for that rather than foreclosing it.

