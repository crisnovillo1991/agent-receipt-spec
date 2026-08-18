/* air-evidence core — browser/node ESM port of the Python reference.
 * JCS canonicalization (no-float subset), Ed25519 via WebCrypto, per-agent
 * hash chain, Merkle anchoring, deterministic adjudication D1–D6.
 * All parties fictitious `.example` entities. Reference/demo only:
 * keys are ephemeral and live in page memory.
 */

const te = new TextEncoder();
const subtle = globalThis.crypto.subtle;

/* ---------------- JCS canonicalization (no-float subset) ---------------- */

export function canonicalize(v) {
  return te.encode(ser(v));
}

function ser(v) {
  if (v === null) return "null";
  const t = typeof v;
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") {
    if (!Number.isInteger(v))
      throw new TypeError("floats are prohibited by air-evidence/0.1");
    if (Math.abs(v) > Number.MAX_SAFE_INTEGER)
      throw new RangeError("integer outside IEEE-754 safe range");
    return String(v);
  }
  if (t === "string") return JSON.stringify(v); // JCS-minimal escapes
  if (Array.isArray(v)) return "[" + v.map(ser).join(",") + "]";
  if (t === "object") {
    // JS string sort compares UTF-16 code units = JCS key order.
    const keys = Object.keys(v).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + ser(v[k])).join(",") + "}";
  }
  throw new TypeError("type not allowed in canonical form: " + t);
}

/* ---------------------------- crypto helpers ---------------------------- */

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function b58encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  let pad = 0;
  for (const b of bytes) { if (b === 0) pad++; else break; }
  return "1".repeat(pad) + out;
}

function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function sha256(bytes) {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (h) => Uint8Array.from(h.match(/.{2}/g), (x) => parseInt(x, 16));

export function nowIso() {
  return new Date().toISOString();
}

export function signingBody(obj) {
  const { signatures, ...body } = obj;
  return body;
}

export async function hashObject(obj) {
  return "sha256:" + hex(await sha256(canonicalize(signingBody(obj))));
}

export async function hashText(text) {
  return "sha256:" + hex(await sha256(te.encode(text)));
}

export async function makeKeyPair() {
  const kp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
  return {
    privateKey: kp.privateKey,
    publicKey: kp.publicKey,
    publicRaw: raw,
    didKey: "did:key:z" + b58encode(new Uint8Array([0xed, 0x01, ...raw])),
  };
}

export async function signObject(obj, { role, kid, keypair, signedAt }) {
  const sig = new Uint8Array(
    await subtle.sign("Ed25519", keypair.privateKey, canonicalize(signingBody(obj)))
  );
  const entry = {
    role, kid, alg: "EdDSA",
    sig: b64url(sig),
    signed_at: signedAt || nowIso(),
  };
  (obj.signatures ||= []).push(entry);
  return entry;
}

export async function verifySignature(obj, sigEntry, publicRaw) {
  try {
    const pub = await subtle.importKey("raw", publicRaw, { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify(
      "Ed25519", pub, b64urlDecode(sigEntry.sig), canonicalize(signingBody(obj))
    );
  } catch { return false; }
}

export class DIDRegistry {
  #keys = new Map();
  register(did, kid, publicRaw) {
    if (!this.#keys.has(did)) this.#keys.set(did, new Map());
    this.#keys.get(did).set(kid, publicRaw);
  }
  resolve(kid) {
    const did = kid.split("#", 1)[0];
    return this.#keys.get(did)?.get(kid) ?? null;
  }
}

/* --------------------------- mandate & receipt -------------------------- */

export const KNOWN_CONSTRAINTS = new Set([
  "max_total_amount_minor", "max_per_tx_amount_minor", "currency",
  "max_transactions", "categories", "counterparties",
  "valid_from", "valid_until", "human_approval_above_minor",
]);

export async function issueMandate(p) {
  const mandate = {
    profile: "air-evidence/0.1",
    air_version: "0.3",
    type: "mandate",
    mandate_id: crypto.randomUUID(),
    principal: {
      id: p.principalDid,
      legal_entity: {
        jurisdiction: p.jurisdiction,
        registration_hash: await hashText("registration:" + p.principalDid),
      },
    },
    agent_id: p.agentDid,
    operator_id: p.operatorDid,
    authorization: {
      instruction_hash: await hashText(p.instructionText),
      constraints: p.constraints,
    },
    issued_at: p.issuedAt || nowIso(),
  };
  await signObject(mandate, { role: "principal", kid: p.principalKid, keypair: p.principalKeypair });
  return mandate;
}

export async function termsHash(terms) {
  return "sha256:" + hex(await sha256(canonicalize(terms)));
}

export async function humanApproval(terms, principalKid, principalKeypair) {
  const block = { terms_hash: await termsHash(terms), approved_at: nowIso() };
  await signObject(block, { role: "principal", kid: principalKid, keypair: principalKeypair });
  return block;
}

export async function buildReceipt(p) {
  return {
    profile: "air-evidence/0.1",
    air_version: "0.3",
    type: "transaction_receipt",
    receipt_id: crypto.randomUUID(),
    mandate_ref: { mandate_id: p.mandate.mandate_id, mandate_hash: await hashObject(p.mandate) },
    prev_receipt_hash: p.prev,
    seq: p.seq,
    identity: p.identity,
    decision_context: p.decisionContext,
    terms: p.terms,
    outcome: {
      status: p.outcomeStatus,
      settled_at: p.settledAt,
      delivery: { expected_by: null, confirmation_hash: null },
    },
    timestamps: { decision_at: p.decisionAt, authorized_at: p.authorizedAt, settled_at: p.settledAt },
    human_approval: p.humanApprovalBlock ?? null,
    refs: [],
  };
}

/* ------------------------------ chain/Merkle ----------------------------- */

async function h2(a, b) {
  const cat = new Uint8Array(a.length + b.length);
  cat.set(a); cat.set(b, a.length);
  return sha256(cat);
}

export class MerkleTree {
  constructor(leaves) {
    if (!leaves.length) throw new Error("empty tree");
    this.levels = [leaves.slice()];
  }
  static async build(leaves) {
    const t = new MerkleTree(leaves);
    while (t.levels.at(-1).length > 1) {
      const prev = t.levels.at(-1), nxt = [];
      for (let i = 0; i < prev.length; i += 2)
        nxt.push(i + 1 < prev.length ? await h2(prev[i], prev[i + 1]) : prev[i]);
      t.levels.push(nxt);
    }
    return t;
  }
  get root() { return "sha256:" + hex(this.levels.at(-1)[0]); }
  proof(index) {
    const path = [];
    for (const level of this.levels.slice(0, -1)) {
      const sib = index ^ 1;
      if (sib < level.length)
        path.push({ hash: "sha256:" + hex(level[sib]), side: sib > index ? "right" : "left" });
      index = Math.floor(index / 2);
    }
    return path;
  }
  static async verify(leaf, path, root) {
    let node = leaf;
    for (const step of path) {
      const sib = unhex(step.hash.split(":")[1]);
      node = step.side === "right" ? await h2(node, sib) : await h2(sib, node);
    }
    return "sha256:" + hex(node) === root;
  }
}

export class ReceiptLog {
  constructor(operatorDid, operatorKid, operatorKp) {
    this.operatorDid = operatorDid;
    this.operatorKid = operatorKid;
    this.operatorKp = operatorKp;
    this.entries = [];
    this.byHash = new Map();
    this.streams = new Map();
    this.anchors = [];
    this._anchoredUpto = 0;
  }
  async append(receipt) {
    const agent = receipt.identity.agent_id;
    if (!this.streams.has(agent)) this.streams.set(agent, []);
    const stream = this.streams.get(agent);
    const expectedPrev = stream.length ? stream.at(-1) : null;
    if ((receipt.prev_receipt_hash ?? null) !== expectedPrev)
      throw new Error("prev_receipt_hash does not match agent stream head");
    if (receipt.seq !== stream.length + 1)
      throw new Error("seq is not monotonic for agent stream");
    const rh = await hashObject(receipt);
    this.entries.push(receipt);
    this.byHash.set(rh, receipt);
    stream.push(rh);
    return rh;
  }
  async anchor(anchoredAt) {
    const start = this._anchoredUpto, end = this.entries.length;
    if (start === end) throw new Error("nothing to anchor");
    const hashes = [];
    for (const r of this.entries.slice(start, end)) hashes.push(await hashObject(r));
    const tree = await MerkleTree.build(hashes.map((h) => unhex(h.split(":")[1])));
    const anchor = {
      profile: "air-evidence/0.1",
      type: "anchor",
      log_operator: this.operatorDid,
      range: [start, end],
      receipt_hashes: hashes,
      merkle_root: tree.root,
      anchor_method: "local-signed-timestamp (stand-in for RFC 3161 TSA)",
      anchored_at: anchoredAt || nowIso(),
    };
    await signObject(anchor, { role: "log_operator", kid: this.operatorKid, keypair: this.operatorKp });
    this.anchors.push(anchor);
    this._anchoredUpto = end;
    return anchor;
  }
  async inclusionProof(receiptHash) {
    for (const anchor of this.anchors) {
      const idx = anchor.receipt_hashes.indexOf(receiptHash);
      if (idx !== -1) {
        const tree = await MerkleTree.build(
          anchor.receipt_hashes.map((h) => unhex(h.split(":")[1]))
        );
        return { anchor, leafIndex: idx, path: tree.proof(idx) };
      }
    }
    return null;
  }
  async verifyStream(agentDid) {
    let prev = null, i = 1;
    for (const rh of this.streams.get(agentDid) ?? []) {
      const r = this.byHash.get(rh);
      if ((await hashObject(r)) !== rh) return false;
      if ((r.prev_receipt_hash ?? null) !== prev || r.seq !== i) return false;
      prev = rh; i++;
    }
    return true;
  }
}

/* ---------------------------- adjudication D1–D6 ------------------------ */

const sigByRole = (obj, role) => (obj.signatures ?? []).find((s) => s.role === role) ?? null;

async function verifyRole(obj, role, registry) {
  const sig = sigByRole(obj, role);
  if (!sig) return [false, `missing ${role} signature`];
  const pub = registry.resolve(sig.kid ?? "");
  if (!pub) return [false, `unresolvable kid for ${role}: ${sig.kid}`];
  if (!(await verifySignature(obj, sig, pub))) return [false, `${role} signature does not verify`];
  return [true, "ok"];
}

export async function fileClaim(p) {
  const claim = {
    profile: "air-evidence/0.1",
    type: "claim",
    claim_id: crypto.randomUUID(),
    claimant: p.claimantDid,
    refs: [await hashObject(p.receipt)],
    asserted_loss_minor: p.assertedLossMinor,
    currency: p.currency,
    reason_hash: await hashText(p.reason),
    filed_at: nowIso(),
  };
  await signObject(claim, { role: "claimant", kid: p.claimantKid, keypair: p.claimantKp });
  return claim;
}

export async function adjudicate(p) {
  const { claim, receipt, mandate, log, registry } = p;
  const checks = {};
  const violations = [];
  let verdict = null;

  // D1 — signatures + presence in log
  const d1 = [];
  for (const role of ["agent", "counterparty"]) {
    const [ok, msg] = await verifyRole(receipt, role, registry);
    if (!ok) d1.push(msg);
  }
  if (sigByRole(receipt, "witness")) {
    const [ok, msg] = await verifyRole(receipt, "witness", registry);
    if (!ok) d1.push(msg);
  }
  const rh = await hashObject(receipt);
  if (!log.byHash.has(rh)) d1.push("receipt hash not present in log (content altered?)");
  if (d1.length) { checks.D1_signatures = "FAIL: " + d1.join("; "); verdict = "INVALID_EVIDENCE"; }
  else checks.D1_signatures = "PASS";

  // D2 — chain + anchoring
  if (!verdict) {
    const agent = receipt.identity.agent_id;
    const proof = await log.inclusionProof(rh);
    if (!(await log.verifyStream(agent))) {
      checks.D2_chain = "FAIL: agent stream broken (prev/seq/hash mismatch)";
      verdict = "BROKEN_CHAIN";
    } else if (!proof) {
      checks.D2_chain = "FAIL: receipt not covered by any anchor";
      verdict = "BROKEN_CHAIN";
    } else {
      const [okAnchor, msg] = await verifyRole(proof.anchor, "log_operator", registry);
      const okPath = await MerkleTree.verify(
        unhex(rh.split(":")[1]), proof.path, proof.anchor.merkle_root
      );
      if (!okAnchor || !okPath) {
        checks.D2_chain = `FAIL: anchor/${msg} path_ok=${okPath}`;
        verdict = "BROKEN_CHAIN";
      } else {
        checks.D2_chain = `PASS (anchored: ${proof.anchor.anchor_method} ${proof.anchor.anchored_at})`;
      }
    }
  }

  // D3 — mandate resolution
  if (!verdict) {
    if (receipt.mandate_ref.mandate_hash !== (await hashObject(mandate))) {
      checks.D3_mandate = "FAIL: mandate_hash mismatch"; verdict = "MANDATE_MISMATCH";
    } else {
      const [ok, msg] = await verifyRole(mandate, "principal", registry);
      if (!ok) { checks.D3_mandate = "FAIL: " + msg; verdict = "MANDATE_MISMATCH"; }
      else checks.D3_mandate = "PASS (mandate_hash match)";
    }
  }

  const c = mandate.authorization.constraints;

  // D4 — temporal validity
  if (!verdict) {
    const d = receipt.timestamps.decision_at;
    if (!(c.valid_from <= d && d <= c.valid_until)) {
      checks.D4_temporal = `FAIL: decision_at ${d} outside mandate window`;
      verdict = "EXPIRED_MANDATE";
    } else checks.D4_temporal = "PASS";
  }

  // D6 — unknown constraints (fail-safe, evaluated before D5 verdicts)
  const unknown = Object.keys(c).filter((k) => !KNOWN_CONSTRAINTS.has(k));
  if (!verdict && unknown.length) {
    checks.D6_unknown_constraints =
      `FAIL: adjudicator does not understand [${unknown.sort().join(", ")}]; fail-safe`;
    verdict = "INDETERMINATE";
  }

  // D5 — typed constraints
  if (!verdict) {
    const t = receipt.terms;
    if (t.currency !== c.currency)
      violations.push({ constraint: "currency", expected: c.currency, actual: t.currency });
    if (c.max_per_tx_amount_minor != null && t.amount_minor > c.max_per_tx_amount_minor)
      violations.push({ constraint: "max_per_tx_amount_minor",
        expected: c.max_per_tx_amount_minor, actual: t.amount_minor });

    const settled = log.entries.filter((r) =>
      r.mandate_ref.mandate_id === mandate.mandate_id &&
      r.outcome.status === "settled" &&
      r.seq <= receipt.seq &&
      r.identity.agent_id === receipt.identity.agent_id
    );
    const total = settled.reduce((s, r) => s + r.terms.amount_minor, 0);
    if (total > c.max_total_amount_minor)
      violations.push({ constraint: "max_total_amount_minor",
        expected: c.max_total_amount_minor, actual: total });
    if (c.max_transactions != null && settled.length > c.max_transactions)
      violations.push({ constraint: "max_transactions",
        expected: c.max_transactions, actual: settled.length });
    if (!c.categories.includes(t.category))
      violations.push({ constraint: "categories", expected: c.categories, actual: t.category });
    if (c.counterparties.mode === "allowlist" &&
        !(c.counterparties.ids ?? []).includes(t.counterparty.id))
      violations.push({ constraint: "counterparties",
        expected: c.counterparties.ids ?? [], actual: t.counterparty.id });

    if (c.human_approval_above_minor != null && t.amount_minor > c.human_approval_above_minor) {
      const ha = receipt.human_approval;
      let haOk = false;
      if (ha && ha.terms_hash === (await termsHash(t))) {
        const [ok] = await verifyRole(ha, "principal", registry);
        haOk = ok;
      }
      if (!haOk)
        violations.push({ constraint: "human_approval_above_minor",
          expected: `principal signature over terms_hash for amounts > ${c.human_approval_above_minor}`,
          actual: "human_approval: " + (ha ? "invalid" : "null") });
    }

    checks.D5_constraints = violations.length ? `FAIL: ${violations.length} violation(s)` : "PASS";
    verdict = violations.length ? "EXCEEDED_MANDATE" : "WITHIN_MANDATE";
  }

  const adjudication = {
    profile: "air-evidence/0.1",
    type: "adjudication",
    adjudication_id: crypto.randomUUID(),
    adjudicator: p.adjudicatorDid,
    refs: [await hashObject(claim), rh],
    checks, verdict, violations,
    resolution_path: verdict !== "INDETERMINATE" ? "auto" : "human_review",
    adjudicated_at: nowIso(),
  };
  await signObject(adjudication, {
    role: "adjudicator", kid: p.adjudicatorKid, keypair: p.adjudicatorKp,
  });
  return adjudication;
}
