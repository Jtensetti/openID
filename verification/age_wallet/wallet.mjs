import { CoseKey } from '@owf/mdoc';
import { keyPair, present, verifyCredential } from './mdoc.mjs';

// In-memory software wallet for private interop, not iPhone key storage.
// No import/export/backup API: restarting loses both unused and spent keys.
export class OneUseAgeWallet {
  #entries = [];
  #pins;
  #issuing = false;
  #closed = false;

  constructor(signerPins) {
    if (!Array.isArray(signerPins) || !signerPins.length || signerPins.length > 16) throw new Error('Signer pins required');
    this.#pins = signerPins.map(pin => Buffer.from(pin));
  }
  get remaining() { return this.#entries.length; }

  async issueBatch(issuer, count) {
    if (this.#closed || this.#issuing || typeof issuer !== 'function' || !Number.isInteger(count) ||
        count < 1 || count + this.remaining > 30) throw new Error('Issuance unavailable');
    this.#issuing = true;
    const batch = [];
    try {
      for (let i = 0; i < count; i++) {
        const keys = keyPair();
        // A real issuer must authenticate the holder and attest these keys.
        const credential = await issuer(Object.freeze(keys.publicKey));
        const document = await verifyCredential(credential, this.#pins);
        if (!Buffer.from(document.issuerAuth.mobileSecurityObject.deviceKeyInfo.deviceKey.publicKey)
            .equals(Buffer.from(CoseKey.fromJwk(keys.publicKey).publicKey))) throw new Error('Holder key mismatch');
        batch.push({ credential, holderKey: keys.privateKey });
      }
      if (this.#closed) throw new Error('Wallet closed');
      this.#entries.push(...batch);
    } finally {
      this.#issuing = false;
    }
  }

  async present({ request, browserOrigin, approvedOrigin }) {
    if (this.#closed || !this.remaining) throw new Error('No unused age proof');
    // Remove synchronously before any await. Failure also burns the proof;
    // two parallel presentations can never select the same device key.
    const entry = this.#entries.shift();
    const response = await present({ ...entry, request, browserOrigin, approvedOrigin, signerPins: this.#pins });
    if (this.#closed) throw new Error('Wallet closed');
    return response;
  }

  close() {
    this.#closed = true;
    this.#entries = [];
  }
}
