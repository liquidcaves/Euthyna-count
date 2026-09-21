#!/usr/bin/env node
// Checks Euthyna's published count record — independently of Euthyna's own code.
//
//   node verify.mjs checkpoints.json
//
// Needs only Node 20 or later: no packages, nothing downloaded. It reimplements the method in
// METHOD.md from scratch on purpose — a check that reused Euthyna's code would only prove that
// Euthyna agrees with itself.
//
// For every Issue it checks:
//   1. the checkpoints form one unbroken chain: numbered 1, 2, 3 … with no gaps, each linked to the
//      hash of the one before, time moving forward, the running total never falling;
//   2. every signature was made by the private half of the published public key, and every
//      time-stamp receipt is about that checkpoint (its hash is inside it) — full verification of
//      the authority's own signature is `openssl ts -verify`, as METHOD.md explains;
//   3. for a CLOSED Issue: the FINAL day's published tally and secret reproduce its seal, the
//      tally adds up, and it matches the checkpoint's total. Earlier days stay sealed but
//      unopened; an earlier day that IS opened is reported as a problem (METHOD.md explains why).
// It prints every problem it finds, and exits 1 if there were any.

import { readFileSync } from 'node:fs'

const subtle = globalThis.crypto.subtle
const enc = new TextEncoder()

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  return `{${Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
    .join(',')}}`
}

async function sha256Hex(text) {
  const digest = new Uint8Array(await subtle.digest('SHA-256', enc.encode(text)))
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('')
}

const bytes = (b64) => Uint8Array.from(Buffer.from(b64, 'base64'))

function tallyProblems(t) {
  const problems = []
  const whole = (n) => Number.isInteger(n) && n >= 0
  const inOrder = (list, where) => {
    if (list.length !== t.answers.length || list.some((c, i) => c.answer !== t.answers[i] || !whole(c.count))) {
      problems.push(`${where}: answers missing, out of order, or not whole numbers`)
    }
  }
  inOrder(t.national, 'national')
  let seatTotal = 0
  for (const s of t.seats) {
    seatTotal += s.responses
    if (s.answers) {
      inOrder(s.answers, `seat ${s.seat}`)
      const sum = s.answers.reduce((n, c) => n + c.count, 0)
      if (sum !== s.responses) problems.push(`seat ${s.seat}: answers add to ${sum}, not ${s.responses}`)
    }
  }
  const national = t.national.reduce((n, c) => n + c.count, 0)
  if (national !== seatTotal) problems.push(`national answers add to ${national}, the seats to ${seatTotal}`)
  return problems
}

function canonicalTally(t) {
  return canonicalJson({ ...t, seats: [...t.seats].sort((a, b) => (a.seat < b.seat ? -1 : a.seat > b.seat ? 1 : 0)) })
}

function tallyTotal(t) {
  return t.national.reduce((n, c) => n + c.count, 0)
}

async function main() {
  const file = process.argv[2]
  if (!file) {
    console.error('usage: node verify.mjs checkpoints.json')
    process.exit(2)
  }
  const record = JSON.parse(readFileSync(file, 'utf8'))
  const problems = []
  const note = (issue, text) => problems.push(`${issue}: ${text}`)
  if (record.format !== 'euthyna-record/1') note('record', `unknown format "${record.format}"`)
  if (record.signatureAlgorithm !== 'ECDSA-P256-SHA256') note('record', `unknown signature algorithm`)

  const keys = {}
  for (const [id, spki] of Object.entries(record.publicKeys ?? {})) {
    keys[id] = await subtle.importKey('spki', bytes(spki), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  }

  let checked = 0
  let signed = 0
  let receipts = 0
  for (const entry of record.issues ?? []) {
    const cps = entry.checkpoints ?? []
    if (cps.length === 0) note(entry.issue, 'no checkpoints')
    let previous = null
    for (let i = 0; i < cps.length; i++) {
      const c = cps[i]
      const bare = {
        format: c.format, issue: c.issue, sequence: c.sequence, takenAt: c.takenAt,
        responses: c.responses, seal: c.seal, previous: c.previous,
      }
      if (c.format !== 'euthyna-checkpoint/1') note(entry.issue, `checkpoint ${i + 1}: unknown format`)
      if (c.issue !== entry.issue) note(entry.issue, `checkpoint ${i + 1}: belongs to "${c.issue}"`)
      if (c.sequence !== i + 1) note(entry.issue, `checkpoint ${i + 1}: numbered ${c.sequence}`)
      if (c.previous !== previous) note(entry.issue, `checkpoint ${i + 1}: not linked to the one before`)
      if (i > 0 && !(c.takenAt > cps[i - 1].takenAt)) note(entry.issue, `checkpoint ${i + 1}: not later than the one before`)
      if (i > 0 && c.responses < cps[i - 1].responses) note(entry.issue, `checkpoint ${i + 1}: total fell`)
      if (c.signature) {
        const key = keys[c.signedWith]
        const ok = key && (await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, bytes(c.signature), enc.encode(canonicalJson(bare))))
        if (!ok) note(entry.issue, `checkpoint ${i + 1}: signature does not check`)
        else signed++
      }
      const hash = await sha256Hex(canonicalJson(bare))
      for (const t of c.timestamps ?? []) {
        // ⚠️ Buffer.includes, not Uint8Array.includes: the latter looks for ONE byte, so it said
        // every genuine receipt was for another checkpoint — caught by its test, 2026-09-19.
        if (!Buffer.from(t.receipt, 'base64').includes(Buffer.from(hash, 'hex'))) {
          note(entry.issue, `checkpoint ${i + 1}: the ${t.authority} receipt is for a different checkpoint`)
        } else receipts++
      }
      previous = hash
      checked++
    }

    if (entry.state === 'closed') {
      // Only the FINAL day is opened (METHOD.md, "Why only the final day is opened"). Two opened
      // days could be subtracted seat by seat to reveal one person's vote, so an earlier day
      // being opened is itself a problem, not a bonus.
      const opened = entry.opened ?? []
      const last = cps.length
      if (!opened.some((o) => o.sequence === last)) note(entry.issue, `closed, but its final day (${last}) is not opened`)
      for (const o of opened) {
        if (o.sequence !== last) note(entry.issue, `day ${o.sequence} is opened — only the final day may be, or votes can be worked out by subtraction`)
        const c = cps[o.sequence - 1]
        for (const p of tallyProblems(o.tally)) note(entry.issue, `day ${o.sequence}: ${p}`)
        const seal = await sha256Hex(`euthyna-tally-seal/1\n${canonicalTally(o.tally)}\n${o.secret}`)
        if (!c || seal !== c.seal) note(entry.issue, `day ${o.sequence}: the tally and secret do not reproduce the seal`)
        if (c && tallyTotal(o.tally) !== c.responses) note(entry.issue, `day ${o.sequence}: the tally adds to ${tallyTotal(o.tally)}, the checkpoint says ${c.responses}`)
      }
    } else if (entry.opened) {
      note(entry.issue, 'an OPEN Issue published its secrets — its running result is exposed')
    }
  }

  console.log(
    `checked ${checked} checkpoint(s) across ${(record.issues ?? []).length} Issue(s); ` +
      `${signed} signature(s) valid; ${receipts} time-stamp receipt(s) about the right checkpoint`,
  )
  if (checked === 0) problems.push('record: nothing to check')
  if (problems.length > 0) {
    for (const p of problems) console.error(`PROBLEM  ${p}`)
    console.error(`${problems.length} problem(s) found`)
    process.exit(1)
  }
  console.log('OK — nothing in this record was rewritten')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
