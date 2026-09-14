# Worked example: a re-encoding that passes, a substitution that fails

This is the chain from SPEC §5 with every digest computed. [`chain.json`](chain.json) holds the records and the exact wire payloads their receivers got. `impl/verify.py` recomputes every digest below from those bytes and rebuilds the graph. `impl/build_vectors.py` generates everything in the tables; none of it is typed by hand.

<!-- generated:example-records (impl/build_vectors.py) -->
| seq | from → to | rel | subject | observed | prev | address |
|---:|---|---|---|---|---|---|
| 0 | seller-0 → buyer-0 | `verbatim` | dataset A `18d898476982…` | wire-0 `084c21bfa689…` | — | `d5c117b41ce4…` |
| 1 | buyer-0 → buyer-1 | `reencoded` | dataset A `18d898476982…` | wire-1 `01d414299211…` | `d5c117b41ce4…` | `76af674c4358…` |
| 2 | buyer-1 → buyer-2 | `verbatim` | dataset B `7b4e2c12b1e9…` | wire-2 `b7a9de196745…` | `76af674c4358…` | `27103b91ee9c…` |

| edge | state | reasons |
|---|---|---|
| seq 1 → seq 0 | **Verified** | — |
| seq 2 → seq 1 | **Failed** | `H2_SUBJECT_CHANGED`, `H2_VERBATIM_BYTES_CHANGED`, `H3_SUBJECT_DISCONTINUITY` |

Payloads: wire-0 is dataset A, 111 bytes; wire-1 is dataset A, 159 bytes; wire-2 is dataset B, 112 bytes.
<!-- /generated:example-records -->

Digests are abbreviated. `chain.json` has them in full.

## What each record asserts

Every record makes the same kinds of claim. `subject` is the canonical identifier of the dataset that moved: `canon.dataset_id` of the payload, the same identifier the `dataset` class gives it. `observed` is the SHA-256 of the exact bytes the receiver got. `prev` is the address of the record before it. `rel` states how this hop relates to that one. The receiver is the only party who saw the bytes, so the receiver makes the record (SPEC §3, Signing; this repository does not implement signing).

**The first record.** seller-0 sends dataset A to buyer-0, who receives `wire-0`. It starts the chain, so it has no `prev`, and there is nothing yet for `rel` to be checked against.

**The second record.** buyer-0 forwards A to buyer-1, but not byte for byte: `wire-1` has its members reordered, is indented, spells the integers as `1.0`, and has `Café` in NFD. The bytes differ, so `observed` moves. The dataset does not change, because canonicalization folds exactly those differences, so `subject` stays A. The record declares `rel: "reencoded"`, and H2 checks that claim against its predecessor: same `subject`, different `observed`. The edge is Verified.

**The third record.** buyer-1 forwards to buyer-2 and declares `rel: "verbatim"`. But the payload buyer-2 received, `wire-2`, is dataset B: a value in `qty` differs. Its `subject` is B's identifier. Nothing in the set bridges A to B: no `derived` record has B as its `result`.

## Which rule catches it

The third edge is Failed. Every reason in the table is computed from the records alone:

- `H3_SUBJECT_DISCONTINUITY`: H3 requires a record's `subject` to equal its predecessor's unless the predecessor is `derived`. This is the substitution, and the rule SPEC §5 names.
- `H2_SUBJECT_CHANGED`: H2's `verbatim` clause also requires the same `subject`. Under this implementation's reading it is the same comparison as H3's. It is reported under both rules because the spec states both.
- `H2_VERBATIM_BYTES_CHANGED`: `verbatim` claims the bytes did not change, but `observed` differs from the predecessor's.

SPEC §5 attributes the failure to H3 alone. The rules as written also fire H2, and the table shows every reason.

The second record is the case the same machinery must *not* flag. `subject` and `observed` sit in different digest contexts, and H2 checks each against the predecessor separately. A reader who trusted `observed` alone would call the second hop tampering. A reader who trusted `rel` alone would miss the third.

Nothing here needs a network, a key, or a clock: order comes from `prev` and `seq` alone. The same three records, without carried addresses, are vector `h3-substitution` in [`vectors/vectors.json`](../vectors/vectors.json), and `impl/verify.py` checks that the two reconstruct the same graph.
