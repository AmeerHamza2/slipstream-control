import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { compactVerify, decodeProtectedHeader } from 'jose';
import { extensionOids } from './der.js';

/**
 * Marker extensions Apple puts on its App Store signing certificates (the same checks
 * Apple's own app-store-server-library performs):
 * - 1.2.840.113635.100.6.11.1 on the leaf: "Mac App Store Receipt Signing", i.e. the
 *   certificate is authorised to sign App Store receipts / transactions / notifications.
 * - 1.2.840.113635.100.6.2.1 on the intermediate: Apple Worldwide Developer Relations CA.
 * Without these checks any certificate Apple ever issued under Root CA G3 (e.g. a
 * developer's own signing cert) could mint "valid" transactions.
 */
export const APPLE_RECEIPT_SIGNING_OID = '1.2.840.113635.100.6.11.1';
export const APPLE_WWDR_INTERMEDIATE_OID = '1.2.840.113635.100.6.2.1';

export class AppleVerificationError extends Error {}

export interface AppleJwsVerifierOptions {
  rootCertificate: X509Certificate;
  now?: () => Date;
}

/**
 * Verifies Apple's JWS (signedPayload, signedTransactionInfo, signedRenewalInfo):
 *  1. header alg must be ES256 and carry an x5c chain [leaf, intermediate, (root)];
 *  2. every certificate must be within its validity window;
 *  3. each certificate must be issued and signed by the next one; issuers must be CAs;
 *  4. the chain must end at the pinned Apple Root CA G3 (from APPLE_ROOT_CA_PATH), either
 *     by including it byte-for-byte or by the last certificate being signed by it;
 *  5. Apple's marker OIDs must be present (see above);
 *  6. finally the JWS signature is verified with the leaf's public key.
 * Online revocation (OCSP) is not checked; see README.
 */
export class AppleJwsVerifier {
  private readonly root: X509Certificate;
  private readonly now: () => Date;

  constructor(opts: AppleJwsVerifierOptions) {
    this.root = opts.rootCertificate;
    this.now = opts.now ?? (() => new Date());
  }

  static fromFile(path: string): AppleJwsVerifier {
    return new AppleJwsVerifier({ rootCertificate: loadCertificate(path) });
  }

  async verify<T = Record<string, unknown>>(jws: string): Promise<T> {
    if (typeof jws !== 'string' || jws.split('.').length !== 3) {
      throw new AppleVerificationError('not a compact JWS');
    }
    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(jws);
    } catch {
      throw new AppleVerificationError('malformed JWS header');
    }
    if (header.alg !== 'ES256') throw new AppleVerificationError('unexpected alg');
    const x5c = header.x5c;
    if (!Array.isArray(x5c) || x5c.length < 2 || x5c.length > 3) {
      throw new AppleVerificationError('x5c must contain 2 or 3 certificates');
    }

    let chain: X509Certificate[];
    try {
      chain = x5c.map((b64) => new X509Certificate(Buffer.from(b64, 'base64')));
    } catch {
      throw new AppleVerificationError('x5c contains an invalid certificate');
    }
    const leaf = chain[0]!;
    this.verifyChain(chain);

    let payload: Uint8Array;
    try {
      ({ payload } = await compactVerify(jws, leaf.publicKey, { algorithms: ['ES256'] }));
    } catch {
      throw new AppleVerificationError('JWS signature invalid');
    }
    try {
      return JSON.parse(Buffer.from(payload).toString('utf8')) as T;
    } catch {
      throw new AppleVerificationError('JWS payload is not JSON');
    }
  }

  private verifyChain(chain: X509Certificate[]): void {
    const now = this.now().getTime();
    for (const cert of [...chain, this.root]) {
      if (now < Date.parse(cert.validFrom) || now > Date.parse(cert.validTo)) {
        throw new AppleVerificationError('certificate outside its validity period');
      }
    }

    for (let i = 0; i < chain.length - 1; i++) {
      const child = chain[i]!;
      const issuer = chain[i + 1]!;
      if (!issuer.ca) throw new AppleVerificationError('issuer certificate is not a CA');
      if (!child.checkIssued(issuer) || !child.verify(issuer.publicKey)) {
        throw new AppleVerificationError('certificate chain signature invalid');
      }
    }

    const last = chain[chain.length - 1]!;
    const isPinnedRoot = last.raw.equals(this.root.raw);
    if (!isPinnedRoot && !(last.checkIssued(this.root) && last.verify(this.root.publicKey))) {
      throw new AppleVerificationError('chain does not lead to the Apple root CA');
    }

    if (!extensionOids(chain[0]!.raw).includes(APPLE_RECEIPT_SIGNING_OID)) {
      throw new AppleVerificationError('leaf certificate lacks the App Store receipt-signing OID');
    }
    if (!extensionOids(chain[1]!.raw).includes(APPLE_WWDR_INTERMEDIATE_OID)) {
      throw new AppleVerificationError('intermediate certificate lacks the Apple WWDR OID');
    }
  }
}

/** Loads a PEM or DER certificate (Apple ships AppleRootCA-G3.cer as DER). */
export function loadCertificate(path: string): X509Certificate {
  return new X509Certificate(readFileSync(path));
}
