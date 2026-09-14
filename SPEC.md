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
| `seq` | integral number, `>= 0`, within ±(2⁵³−1) | position in this artifact's handoff chain |
| `prev` | typed digest reference, `type: "handoff"` | absent **iff** `seq == 0` |
| `rel` | `"verbatim"` | `"reencoded"` | `"derived"` | relation to the predecessor |
| `result` | typed digest reference, `type: "dataset"` | present **iff** `rel == "derived"` |
| `schema_version` | `"1"` |  |
| `address` | string | carries the identifier; **excluded** before hashing |

Typed digest references are closed objects carrying exactly `type`, `digest_alg: "SHA-256"`, and a 64-hex `digest`, as in the `dataset` class. References live only in the payload, never in a `cpb-refs` header, and are not excluded — so a record commits to its subject, its predecessor, and its result.

**There is no timestamp member.** Order comes from `seq` and `prev`. This is deliberate: producer clocks order nothing, and omitting the field removes the temptation to use it.

### Canonicalization

Unchanged from the `dataset` class — the point of a shared serializer:

1. **Admit and validate** — strict UTF-8, no BOM, well-formed JSON, no duplicate member names after escape decoding, no non-scalar Unicode, every number token mathematically integral and in range.  
2. **Transform** — NFC-fold every string and member name, reject names colliding after folding, enforce the closed shape above, normalize reference objects.  
3. **Exclude** the top-level `address`.  
4. **Apply** RFC 8785 JCS, SHA-256, lowercase hex.

Validation precedes exclusion, so an excluded field cannot hide malformed input.

---

## 3\. Consistency rules

These are what make `rel` a checkable claim rather than a declaration.

The vectors in [`vectors/vectors.json`](vectors/vectors.json) check these rules; each vector names the rule it exercises.

**H1 — relation/result coupling.** `rel: "derived"` requires `result` present and `result.digest != subject.digest`. `verbatim` and `reencoded` require `result` absent.

**H2 — relation is verified, not asserted.** Against the predecessor record P:

- `verbatim` requires `observed.digest == P.observed.digest` and `subject.digest == P.subject.digest`.  
- `reencoded` requires `subject.digest == P.subject.digest` and `observed.digest != P.observed.digest`.  
- `derived` requires `subject.digest == P.subject.digest`; the next record in the chain takes `result` as its `subject`.

A record whose declared `rel` contradicts its digests is **Failed**, not merely inconsistent.

**H3 — chain integrity.** `prev` absent iff `seq == 0`. Otherwise `prev` MUST resolve to a record P with `P.seq == seq - 1`, and `P.subject == subject` unless `P.rel == "derived"`, in which case `P.result == subject`.

**H4 — reconstruction determinism.** The handoff graph is computed **only** by following `prev`. No ordering heuristic, no timestamp tiebreak, no agent-interleaving assumption. Normatively:

> Any two conformant analyzers MUST recover the same handoff graph from the same record set.

Edges report a CPB reference state — *Verified*, *Failed*, *Unresolved*, *Malformed* — plus the profile state *Cyclic*, since under honest content addressing a revisited node signals a forged reference. No non-Verified state counts as a pass.

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
- `seq` is per (subject, chain); concurrent forks of one artifact are out of scope for v0.1 and should be named as such.

