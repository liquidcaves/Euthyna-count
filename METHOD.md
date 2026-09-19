# The method

How Euthyna seals its count, and how to check it. Everything here can be reimplemented without any
of Euthyna's code.

## The published tally — `euthyna-tally/1`

The count of one Issue exactly as the closed Issue page publishes it:

```json
{
  "format": "euthyna-tally/1",
  "issue": "<issue address>",
  "answers": ["<answer 1>", "<answer 2>", "..."],
  "national": [{ "answer": "<answer 1>", "count": 0 }, "..."],
  "seats": [{ "seat": "<seat code>", "responses": 0, "answers": [ ... ] | null }]
}
```

- `answers` is the question's own order; every list of counts follows it exactly.
- A seat's `answers` is `null` where the site withholds that seat's split (too few responses to
  publish safely); its `responses` total is always present.
- Every count is a whole number ≥ 0; a seat's answers add up to its `responses`; the national
  answers add up to the sum of every seat's `responses`.

**Canonical form** — the exact bytes that are sealed: JSON with no whitespace, **every object's
keys sorted** by code point, **seats sorted by `seat`**, arrays otherwise in the order above.

## The seal

```
seal = SHA-256( "euthyna-tally-seal/1" + "\n" + canonical tally + "\n" + secret )
```

as lowercase hex. `secret` is 32 random bytes as 64 lowercase hex characters, **fresh for every
seal**, kept private while the Issue is open and published when it closes. Without it, the small
numbers in a tally could be guessed from the seal by trying every combination, which would leak an
open Issue's result.

## The daily checkpoint — `euthyna-checkpoint/1`

```json
{
  "format": "euthyna-checkpoint/1",
  "issue": "<issue address>",
  "sequence": 1,
  "takenAt": "2026-10-01T00:00:00Z",
  "responses": 0,
  "seal": "<seal>",
  "previous": "<hash of the previous checkpoint> | null"
}
```

`previous` is `SHA-256(canonical form of the previous checkpoint)`, null for the first. So the
checkpoints form one chain: changing any day breaks every link after it.

## The signature

Each checkpoint is signed with ECDSA on the P-256 curve, SHA-256, over the UTF-8 bytes of the
checkpoint's canonical form (the checkpoint fields above, keys sorted, no whitespace). The signature
is published as the raw 64 bytes r‖s in base64, beside the ARN of the AWS KMS key that made it. The
record's `publicKeys` maps that ARN to the key's public half (SubjectPublicKeyInfo DER, base64). The
private half was created inside AWS KMS and cannot be exported.

## Checking it, once an Issue closes

1. Every checkpoint you kept is in the chain: numbered 1, 2, 3 … with no gaps, each `previous`
   matching the hash of the one before, time moving forward, `responses` never falling.
2. For each checkpoint, the published tally for that day and its secret reproduce its `seal`.
3. Between any two days, no count — national, or in any seat whose split is shown on both days —
   went down, and no seat disappeared.

`verify.mjs` in this repository does all of these checks, including the signatures. It is written
from this description alone, so it doesn't depend on any of Euthyna's code.

