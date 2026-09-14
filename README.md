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
  network guard          10/10
  sha256sums             20/20
  canon.py provenance      4/4
  cross-build record       1/1
  canonicalization       11/11
  carried-address          1/1
  commitment               5/5
  admission              27/27
  H1                       5/5
  H2                       5/5
  H3                       9/9
  H4                       3/3
  H4 repeat run            3/3
  cycle guard              1/1
  example                  7/7
  generated docs           3/3
  TOTAL                115/115  PASS
```
<!-- /generated:verify-output -->

Apart from `vectors/SHA256SUMS` itself, `README.md` is the only committed file that `SHA256SUMS` does not cover, and it cannot be: the block above records `verify.py`'s check of `SHA256SUMS`, so it is written after that file. `verify.py` checks it instead, byte for byte against its own output, and checks this README's other generated blocks against the data.

`impl/verify.py` takes no arguments and needs no API key. It checks every file listed in `vectors/SHA256SUMS`; checks `impl/canon.py` against `impl/CANON_PROVENANCE` (its hash, the commit this README and `NOTICE` quote, and the helpers `impl/handoff.py` calls); checks that `vectors/CROSS_BUILD` was recorded against the current `vectors.json`; runs every vector; runs each H4 vector a second time and compares the output bytes; checks the worked example; and checks that the generated blocks in this README and in `example/README.md` still match the data. It exits 1 on any failure. `shasum -a 256 -c vectors/SHA256SUMS` checks the file hashes without Python.

The network gate is that verification completes with no network available. On macOS, `sandbox-exec -p '(version 1)(allow default)(deny network*)' python impl/verify.py` runs it with all network access denied. As defence in depth, and explicitly not a sandbox, `verify.py` also patches Python's socket lookup and send calls before importing the code it checks, so an accidental network call fails loudly, and it probes each patched call. Subprocesses, C extensions and raw system calls route around that guard, and its self-check probes the same list of calls it patches, so it cannot notice a call dropped from that list; the pinned output above would, through the row count.

Start with [`example/README.md`](example/README.md): a benign re-encoding that passes and a substitution that fails.

## What the vectors cover

<!-- generated:vector-counts (impl/build_vectors.py) -->
| category | spec | vectors |
|---|---|---:|
| canonicalization | §2 | 11 |
| carried-address | §2 | 1 |
| commitment | §2 | 5 |
| admission | §2 | 27 |
| H1 | §2 (H1) | 5 |
| H2 | §3 H2, §3 H3 | 5 |
| H3 | §2 (H3), §3 H2, §3 H3, §3 H4 | 9 |
| H4 | §3 H4 | 3 |
| **total** | | **66** |

Built with CPython 3.13.3, Unicode 15.1.0, rfc8785 0.1.4 (recorded in `vectors/BUILD_ENV`).
<!-- /generated:vector-counts -->

- **canonicalization**: spellings that must keep one address. Member order, `seq` as `1`, `1.0` or `1e0`, NFC and NFD in `from` and `to`, `\u` escapes, whitespace and indentation, and a carried `address` that is absent, correct, or another record's.
- **commitment**: changing any committed member moves the address.
- **carried-address**: a record whose carried `address` disagrees with its derived identifier still derives its address, and `check_address` reports it as `differs`.
- **admission**: refusals with a typed code. Duplicate member names after escape decoding (including a duplicate `address`, caught because validation precedes exclusion), a lone surrogate, non-integral and out-of-range numbers, unknown and missing members, digest references with an extra or missing key, uppercase or wrong-length hex, references of the wrong type, and malformed scalar members.
- **H1**: the `rel`/`result` pairing and `result != subject`, now stated in SPEC §2. A record that breaks them has no address.
- **H2**: each declared `rel` checked against the predecessor's observation, including the benign re-encoding.
- **H3**: the SPEC §2 `prev`/`seq` pairing, a `seq` gap, an unresolved `prev`, the substitution, a chain crossing a `derived` record, a forged cycle, and a malformed record inside a set.
- **H4**: one record set in different array orders; one valid record in different spellings, which is one node; and one malformed record in different spellings, which is two entries. Each reconstructs byte-identical graphs.

Every expected address and graph is pinned from this implementation. The vectors are regression and interoperability targets for an independent implementation, not independent evidence.

Vector ids are stable identifiers, not rule assignments. An id names the rule a vector was written against; its `rule` field names the rules that decide it now. The two can drift as the spec settles, and ids are not renamed, because `vectors/vectors.json` is committed under `vectors/SHA256SUMS`.

Unicode's normalization stability policy fixes NFC results for characters already assigned, and every non-ASCII character in the vectors is long assigned, so the vectors should not depend on the Unicode version. A rebuild under other interpreters checks that:

<!-- generated:cross-build (impl/build_vectors.py) -->
`impl/cross_build.py` rebuilt the generated files under other interpreters and compared each byte for byte with the committed one (recorded in `vectors/CROSS_BUILD`):

- Python 3.14.4, Unicode 16.0.0, rfc8785 0.1.4: `vectors/vectors.json` identical, `example/chain.json` identical, `vectors/BUILD_ENV` differs.
- Python 3.9.6, Unicode 13.0.0, rfc8785 0.1.4: `vectors/vectors.json` identical, `example/chain.json` identical, `vectors/BUILD_ENV` differs.
<!-- /generated:cross-build -->

To regenerate, run `python impl/build_vectors.py`. When `vectors.json` changes, `vectors/CROSS_BUILD` goes stale and the build stops until `impl/cross_build.py` has been rerun with at least one other interpreter; then run the build again. A collaborator who regenerates will produce their own `vectors/BUILD_ENV` and `vectors/SHA256SUMS`, and their own `vectors/CROSS_BUILD` if they rerun it, each recording their machine. That is expected; `vectors/vectors.json` itself should come out byte-identical.

## Where this implementation reads the spec

The spec text leaves one point open that code cannot. `impl/handoff.py` settles it as follows, and the vectors pin the result.

- **`Cyclic` is unreachable.** `prev` resolves by recomputed address only. The carried `address` is excluded from the hash and never resolves anything. Each record's hash commits to its `prev`, so a cycle would need a SHA-256 fixpoint. The forged-cycle vector, whose carried addresses point at each other, reports `Unresolved`. `impl/verify.py` exercises the cycle guard directly.

## Open questions

From SPEC §6, and open here too:

- Whether the recorder is the runtime or the receiving agent in a deployment where the runtime is untrusted.
- Whether `derived` needs a transform descriptor, or whether the `result` dataset's own `parents` set already carries it.
- Concurrent forks of one artifact are out of scope for v0.1. (`seq` itself is per chain, not per subject: it counts hops, so it continues across a `derived` hop.)
- The observation gap after a `derived` hop. No party observes `result` before the next hop, so H2 cannot check that hop's `rel`. Either forbid `verbatim` and `reencoded` there and require a fresh origin state, or have the deriving party record its own observation of `result`; the second is recommended, because under the first the unchecked observation after a derivation becomes the baseline for every later hop.
- Whether a conformance profile should be able to require carried-address agreement. This implementation reports disagreement (`check_address`) and does not act on it.

## Scope

This repository is a construction and a determinism property, not a protocol specification. It implements the record shape, the canonicalization, and rules H1–H4 of `SPEC.md`. It does not implement signing, SCITT registration, or replay detection (SPEC §3 "Signing" and the replay row of §4), and it claims no conformance to CPB, SCITT, or any IETF draft. Every example is synthetic, constructed to exercise the rules. It makes no claim about how often re-encoding, substitution, or any other fault occurs in any real deployment.

## Disclosure

Maura Clark authored `uor-jcs-nfc` ([pinned specification](https://github.com/UOR-Foundation/uor-jcs-nfc/blob/303591128094362857791930fdc12b73875d1ff6/SPEC.md)), a related canonicalization that this profile deliberately does not select; its specification, reference implementation, and a provisional RC5 corpus are public, and its final `uor-vectors-v2` corpus is not yet designated. Maura Clark contributes to the UOR Foundation, which is not a dependency of the protocol.

`impl/canon.py` was written by Maura Clark and is vendored unmodified from [`canonical-dataset-lineage`](https://github.com/maurathat/canonical-dataset-lineage) at commit `f60922396b81f44ed181568c922281d9eb81e98f`. See [`NOTICE`](NOTICE).

## Licence and contact

`impl/`, `vectors/`, and `example/chain.json` are licensed under the [Apache License 2.0](LICENSE). `SPEC.md`, the READMEs, and `LICENSES.md` are licensed under [CC BY 4.0](LICENSES/CC-BY-4.0.txt). [`LICENSES.md`](LICENSES.md) gives the full scope.

- Maura Clark ([@maurathat](https://github.com/maurathat)), maura@uor.foundation
- Jin Gao ([@srcJin](https://github.com/srcJin)), usgaojin@gmail.com
