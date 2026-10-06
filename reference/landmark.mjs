import { createPublicKey } from 'node:crypto';
import { requireThat, now, equal, H, D, sign, verify, b64u, keyID } from './core.mjs';
import { signCMS } from './pki.mjs';
import { readControl } from './state.mjs';
import { coverInterval, treeHash, cosignedMessage } from './mtc.mjs';
import { landmarkRelativeCertificate } from './transparency.mjs';

export function parseLandmarks(text, { at = now(), draft06Strict = false, maxActive = 1024 } = {}) {
  requireThat(
    typeof text === 'string' &&
      text.length <= 128 * 1024 &&
      /^(0|[1-9][0-9]*)\n(?:(0|[1-9][0-9]*) (0|[1-9][0-9]*)\n)+$/.test(text),
    'LANDMARK_TEXT',
  );
  const lines = text.trimEnd().split('\n'),
    latest = BigInt(lines.shift());
  requireThat(
    latest < 1n << 48n &&
      lines.length <= maxActive + 1 &&
      BigInt(lines.length) <= latest + (draft06Strict ? 0n : 1n),
    'LANDMARK_COUNT',
  );
  const values = lines.map((l, i) => {
    const [size, expiry] = l.split(' ').map(BigInt);
    requireThat(size < 1n << 48n && expiry <= BigInt(Number.MAX_SAFE_INTEGER), 'LANDMARK_RANGE');
    return { number: latest - BigInt(i), size, expiry };
  });
  for (let i = 0; i < values.length; i++) {
    const v = values[i],
      next = values[i + 1];
    if (v.number === 0n) requireThat(v.size === 0n && v.expiry === 0n, 'LANDMARK_GENESIS');
    if (next) requireThat(v.size > next.size && v.expiry >= next.expiry, 'LANDMARK_ORDER');
  }
  requireThat(values.at(-1).expiry <= BigInt(at), 'LANDMARK_EXPIRED_PREDECESSOR');
  return values;
}

export class LandmarkPublisher {
  constructor({
    journal,
    caID,
    logNumber,
    caKey,
    certificate,
    mirrors,
    policyHash,
    rtmHash,
    membershipEpoch,
  }) {
    Object.assign(this, {
      journal,
      caID,
      logNumber,
      caKey,
      certificate,
      mirrors,
      policyHash,
      rtmHash,
      membershipEpoch,
    });
    this.id = caID + ':' + logNumber;
  }
  allocate(entries, { expiresAt, certificateExpiries }) {
    requireThat(
      entries.length > 0 &&
        certificateExpiries.length === entries.length &&
        certificateExpiries.every((t) => Number.isSafeInteger(t) && t <= expiresAt),
      'LANDMARK_EXPIRY',
    );
    return this.journal.transaction(() => {
      const row = this.journal.get('landmarks', this.id),
        sequence = row?.value.sequence ?? [{ number: 0, size: 0, expiry: 0 }],
        last = sequence.at(-1);
      requireThat(entries.length > last.size && expiresAt >= last.expiry, 'LANDMARK_ALLOCATION');
      const next = { number: last.number + 1, size: entries.length, expiry: expiresAt };
      sequence.push(next);
      this.journal.put('landmarks', this.id, { sequence }, row?.revision ?? -1);
      return next;
    });
  }
  async publish(entries) {
    const sequence = this.journal.get('landmarks', this.id)?.value.sequence;
    requireThat(
      sequence?.length > 1 && sequence.at(-1).size <= entries.length,
      'LANDMARK_SEQUENCE',
    );
    const active = sequence.filter((s) => s.expiry > now()),
      first = active[0]?.number ?? sequence.length - 1,
      published = sequence.slice(Math.max(0, first - 1)).reverse(),
      text =
        sequence.at(-1).number +
        '\n' +
        published.map((s) => s.size + ' ' + s.expiry + '\n').join(''),
      subtrees = [];
    parseLandmarks(text);
    for (const l of active) {
      const previous = sequence[l.number - 1];
      for (const [s, e] of coverInterval(previous.size, l.size)) {
        if (s === e) continue;
        const start = Number(s),
          end = Number(e),
          root = treeHash(entries.slice(start, end)),
          context = { caID: this.caID, logNumber: this.logNumber, start, end, root },
          signatures = [
            {
              cosignerID: this.caID,
              signature: sign(cosignedMessage({ ...context, cosignerID: this.caID }), this.caKey),
            },
          ];
        for (const m of this.mirrors) signatures.push(await m.cosignSubtree(context));
        subtrees.push({ landmark: l.number, start, end, root, expiresAt: l.expiry, signatures });
      }
    }
    const statement = {
      schemaVersion: 1,
      adapterID: 'certconcord-mtc-landmarks-v1',
      caID: this.caID,
      logNumber: this.logNumber,
      sequence: text,
      subtrees,
      policyHash: this.policyHash,
      rtmHash: this.rtmHash,
      membershipEpoch: this.membershipEpoch,
      issuedAt: now(),
      expiresAt: now() + 300,
    };
    return signCMS(
      { content: D('LandmarkDistribution', statement), certificate: this.certificate },
      this.caKey,
    );
  }
  relative(tbs, { entries, index }) {
    const seq = this.journal.get('landmarks', this.id)?.value.sequence,
      l = seq?.find((s) => s.size > index && s.expiry > now());
    requireThat(l && l.number > 0, 'LANDMARK_UNAVAILABLE');
    const range = coverInterval(seq[l.number - 1].size, l.size).find(
      ([s, e]) => BigInt(index) >= s && BigInt(index) < e,
    );
    return landmarkRelativeCertificate(tbs, {
      entries,
      index,
      start: Number(range[0]),
      end: Number(range[1]),
    });
  }
}

export class LandmarkStore {
  constructor({
    journal,
    certificate,
    caID,
    logNumber,
    caPublicKey,
    members,
    threshold,
    policyHash,
    rtmHash,
    membershipEpoch,
  }) {
    Object.assign(this, {
      journal,
      certificate,
      caID,
      logNumber,
      caPublicKey,
      members,
      threshold,
      policyHash,
      rtmHash,
      membershipEpoch,
    });
    this.id = caID + ':' + logNumber;
  }
  accept(envelope, { mode = 'LIVE', at = now() } = {}) {
    const s = readControl(envelope, 'LandmarkDistribution', this.certificate);
    requireThat(
      s.adapterID === 'certconcord-mtc-landmarks-v1' &&
        s.schemaVersion === 1 &&
        s.caID === this.caID &&
        s.logNumber === this.logNumber &&
        s.membershipEpoch === this.membershipEpoch &&
        equal(s.policyHash, this.policyHash) &&
        equal(s.rtmHash, this.rtmHash) &&
        s.issuedAt <= at &&
        s.expiresAt > at,
      'LANDMARK_POLICY',
    );
    const sequence = parseLandmarks(s.sequence, { at }),
      ranges = [];
    for (let i = 0; i < sequence.length - 1; i++)
      if (sequence[i].expiry > BigInt(at)) {
        for (const [start, end] of coverInterval(sequence[i + 1].size, sequence[i].size))
          if (start !== end)
            ranges.push({
              landmark: Number(sequence[i].number),
              start,
              end,
              expiry: sequence[i].expiry,
            });
      }
    requireThat(ranges.length === s.subtrees.length, 'LANDMARK_SUBTREES');
    for (let i = 0; i < ranges.length; i++) {
      const x = ranges[i],
        t = s.subtrees.find(
          (t) =>
            t.landmark === x.landmark && BigInt(t.start) === x.start && BigInt(t.end) === x.end,
        );
      requireThat(
        t && BigInt(t.expiresAt) === x.expiry && t.root.length === 32,
        'LANDMARK_SUBTREE',
      );
      const good = new Set(),
        keys = new Set();
      let ca = false;
      for (const sig of t.signatures) {
        const m =
          sig.cosignerID === this.caID
            ? { publicKey: this.caPublicKey, operatorID: 'CA' }
            : this.members.find((m) => m.id === sig.cosignerID);
        if (!m) continue;
        requireThat(
          verify(
            cosignedMessage({
              cosignerID: sig.cosignerID,
              caID: this.caID,
              logNumber: this.logNumber,
              start: t.start,
              end: t.end,
              root: t.root,
            }),
            sig.signature,
            m.publicKey,
          ),
          'LANDMARK_SIGNATURE',
        );
        if (sig.cosignerID === this.caID) ca = true;
        else {
          const key = b64u(keyID(m.publicKey));
          requireThat(
            !keys.has(key) && !equal(keyID(m.publicKey), keyID(this.caPublicKey)),
            'LANDMARK_KEY_INDEPENDENCE',
          );
          keys.add(key);
          good.add(m.operatorID);
        }
      }
      requireThat(ca && good.size >= this.threshold, 'LANDMARK_QUORUM');
    }
    requireThat(['LIVE', 'HISTORICAL'].includes(mode), 'LANDMARK_MODE');
    if (mode === 'LIVE')
      this.journal.transaction(() => {
        const old = this.journal.get('landmark-store', this.id);
        if (old) {
          requireThat(sequence[0].number >= old.value.number, 'LANDMARK_ROLLBACK');
          for (const entry of sequence) {
            const prior = old.value.sequence.find((v) => v.number === entry.number);
            if (prior)
              requireThat(
                prior.size === entry.size && prior.expiry === entry.expiry,
                'LANDMARK_FORK',
              );
          }
        }
        this.journal.put(
          'landmark-store',
          this.id,
          { number: sequence[0].number, sequence, hash: H('LandmarkDistribution', s) },
          old?.revision ?? -1,
        );
      });
    return s.subtrees.map((t) => ({
      caID: this.caID,
      logNumber: this.logNumber,
      start: t.start,
      end: t.end,
      root: t.root,
      membershipEpoch: this.membershipEpoch,
      policyHash: this.policyHash,
      rtmHash: this.rtmHash,
      mode,
      validFrom: s.issuedAt,
      expiresAt: Math.min(t.expiresAt, s.expiresAt),
    }));
  }
}
