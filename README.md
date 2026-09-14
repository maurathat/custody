# custody: the `handoff` payload class

A `handoff` record describes an event, not an artifact: a dataset passed from one agent to another at a position in a sequence. It cites the dataset that moved by typed digest reference, commits to a digest of the bytes the receiver actually got, and links to its predecessor by that predecessor's content address. One dataset has many handoff records, made by different parties, none of whom need own it.

That is why `handoff` is a separate payload class and not extra members on `dataset`. Hop fields inside the dataset's canonical bytes would move its identifier on every hop, destroying the stability the canonicalization exists to provide. Hop fields excluded from those bytes would be committed by nothing, so a forged hop history would cost nothing. A second class, run through the same canonicalization under its own digest context, commits to each hop without touching the artifact's identity. [`SPEC.md`](SPEC.md) is the draft; this repository checks it.

## Verify

```sh
git clone https://github.com/maurathat/custody
cd custody
python3 -m venv .venv
. .venv/bin/activate
pip install -r impl/requirements.txt
python impl/verify.py
```

Expected output, byte for byte:

<!-- generated:verify-output (impl/build_vectors.py) -->
```
custody verify
  network guard            1/1
  sha256sums               9/9
  canon.py provenance      1/1
  canonicalization       11/11
  commitment               5/5
  admission              25/25
  H1                       5/5
  H2                       5/5
  H3                       9/9
  H4                       2/2
  H4 repeat run            2/2
  cycle guard              1/1
  example                  7/7
  generated docs           2/2
  TOTAL                  85/85  PASS
```
<!-- /generated:verify-output -->

`impl/verify.py` takes no arguments and needs no API key. Before importing anything it checks, it installs a guard that refuses socket connections and name lookups, and the run confirms the guard is in place. It checks every file listed in `vectors/SHA256SUMS`, checks that `impl/canon.py` still has the hash pinned in `impl/CANON_PROVENANCE`, runs every vector, runs each H4 vector a second time and compares the output bytes, checks the worked example, and checks that the generated blocks in this README and in `example/README.md` still match the data. It exits 1 on any failure. `shasum -a 256 -c vectors/SHA256SUMS` checks the file hashes without Python.

Start with [`example/README.md`](example/README.md): a benign re-encoding that passes and a substitution that fails.

## What the vectors cover

<!-- generated:vector-counts (impl/build_vectors.py) -->
| category | spec | vectors |
|---|---|---:|
| canonicalization | §2 | 11 |
| commitment | §2 | 5 |
| admission | §2 | 25 |
| H1 | §3 H1 | 5 |
| H2 | §3 H2 | 5 |
| H3 | §3 H2, H3, H4 | 9 |
| H4 | §3 H4 | 2 |
| **total** | | **62** |

Generated with CPython 3.13.3, Unicode 15.1.0, rfc8785 0.1.4.
<!-- /generated:vector-counts -->

- **canonicalization**: spellings that must keep one address. Member order, `seq` as `1`, `1.0` or `1e0`, NFC and NFD in `from` and `to`, `\u` escapes, whitespace and indentation, and a carried `address` that is absent, correct, or another record's.
- **commitment**: changing any committed member moves the address.
- **admission**: refusals with a typed code. Duplicate member names after escape decoding (including a duplicate `address`, caught because validation precedes exclusion), a lone surrogate, non-integral and out-of-range numbers, unknown and missing members, digest references with an extra or missing key, uppercase or wrong-length hex, references of the wrong type, and malformed scalar members.
- **H1**: `rel` and `result` coupling.
- **H2**: each `rel` checked against the predecessor's digests, including the benign re-encoding.
- **H3**: the record-local `prev` and `seq` rules, a `seq` gap, an unresolved `prev`, the substitution, a chain crossing a `derived` record, a forged cycle, and a malformed record inside a set.
- **H4**: one record set in different array orders, and one record in different spellings, each reconstructing byte-identical graphs.

Every expected address and graph is pinned from this implementation. The vectors are regression and interoperability targets for an independent implementation, not independent evidence.

## Where this implementation reads the spec

The spec text leaves these points open, and code cannot. `impl/handoff.py` settles them as follows, and the vectors pin the result.

- **H2 at a `derived` hop.** Read literally, H2 requires `subject == P.subject` for every `rel`, H3 requires `subject == P.result` when P is derived, and H1 requires `P.result != P.subject`, so no record could ever follow a derived one. This implementation compares against P's outgoing artifact (`P.result` if P is derived, otherwise `P.subject`) in both rules. After a derived hop it skips H2's `observed` clause, because `P.observed` digests the previous artifact's bytes. The first hop after a derivation is therefore not byte-checked.
- **`Cyclic` is unreachable.** `prev` resolves by recomputed address only. The carried `address` is excluded from the hash and never resolves anything. Each record's hash commits to its `prev`, so a cycle would need a SHA-256 fixpoint. The forged-cycle vector, whose carried addresses point at each other, reports `Unresolved`. `impl/verify.py` exercises the cycle guard directly.
- **Carried `address`.** It must be 64 lowercase hex digits, as in the `dataset` class, but any such value is accepted. A wrong carried address changes neither the derived address nor the graph.

## Open questions

From SPEC §6, and open here too:

- Whether the recorder is the runtime or the receiving agent in a deployment where the runtime is untrusted.
- Whether `derived` needs a transform descriptor, or whether the `result` dataset's own `parents` set already carries it.
- `seq` is per (subject, chain). Concurrent forks of one artifact are out of scope for v0.1.

## Scope

This repository is a construction and a determinism property, not a protocol specification. It implements the record shape, the canonicalization, and rules H1–H4 of `SPEC.md`. It does not implement signing, SCITT registration, or replay detection (SPEC §3 "Signing" and the replay row of §4), and it claims no conformance to CPB, SCITT, or any IETF draft. Every example is synthetic, constructed to exercise the rules. It makes no claim about how often re-encoding, substitution, or any other fault occurs in any real deployment.

## Disclosure

Maura Clark authored `uor-jcs-nfc` ([pinned specification](https://github.com/UOR-Foundation/uor-jcs-nfc/blob/303591128094362857791930fdc12b73875d1ff6/SPEC.md)), a related canonicalization that this profile deliberately does not select; its specification, reference implementation, and a provisional RC5 corpus are public, and its final `uor-vectors-v2` corpus is not yet designated. Maura Clark contributes to the UOR Foundation, which is not a dependency of the protocol.

`impl/canon.py` was written by Maura Clark and is vendored unmodified from [`canonical-dataset-lineage`](https://github.com/maurathat/canonical-dataset-lineage) at commit `f60922396b81f44ed181568c922281d9eb81e98f`. See [`NOTICE`](NOTICE).

## Licence and contact

`impl/`, `vectors/`, and `example/chain.json` are licensed under the [Apache License 2.0](LICENSE). `SPEC.md`, the READMEs, and `LICENSES.md` are licensed under [CC BY 4.0](LICENSES/CC-BY-4.0.txt). [`LICENSES.md`](LICENSES.md) gives the full scope.

- Maura Clark ([@maurathat](https://github.com/maurathat)), maura@uor.foundation
- Jin Gao ([@srcJin](https://github.com/srcJin)), usgaojin@gmail.com
