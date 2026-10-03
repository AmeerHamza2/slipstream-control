/**
 * Generates a throwaway Apple-like PKI (root CA -> WWDR-like intermediate -> leaf with the
 * receipt-signing OID) so the real chain verification code is exercised end to end.
 */
import 'reflect-metadata'; // required by @peculiar/x509's DI container
import { X509Certificate as NodeX509 } from 'node:crypto';
import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { CompactSign } from 'jose';
import { APPLE_RECEIPT_SIGNING_OID, APPLE_WWDR_INTERMEDIATE_OID } from '../../src/apple/jws.js';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const EC: EcKeyGenParams = { name: 'ECDSA', namedCurve: 'P-256' };
const SIG: EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' };
const DER_NULL = new Uint8Array([0x05, 0x00]);
const DAY = 86_400_000;

const genKeys = () => webcrypto.subtle.generateKey(EC, true, ['sign', 'verify']) as Promise<CryptoKeyPair>;

export interface ChainOptions {
  leafOid?: boolean;
  intermediateOid?: boolean;
  leafNotAfter?: Date;
  intermediateIsCa?: boolean;
}

export interface TestPki {
  root: NodeX509;
  rootPem: string;
  /** base64 DER [leaf, intermediate, root], as Apple sends in x5c */
  x5c: string[];
  leafKey: CryptoKey;
  sign(payload: object, opts?: { x5c?: string[]; key?: CryptoKey }): Promise<string>;
}

export async function makeRoot(name = 'Test Apple Root CA - G3') {
  const keys = await genKeys();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: `CN=${name}, O=Test`,
    notBefore: new Date(Date.now() - DAY),
    notAfter: new Date(Date.now() + 3650 * DAY),
    keys,
    signingAlgorithm: SIG,
    extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
  });
  return { cert, keys };
}

export async function makePki(opts: ChainOptions = {}, rootIn?: Awaited<ReturnType<typeof makeRoot>>): Promise<TestPki> {
  const root = rootIn ?? (await makeRoot());

  const intKeys = await genKeys();
  const intExt: x509.Extension[] = [new x509.BasicConstraintsExtension(opts.intermediateIsCa ?? true, 0, true)];
  if (opts.intermediateOid ?? true) intExt.push(new x509.Extension(APPLE_WWDR_INTERMEDIATE_OID, false, DER_NULL));
  const intermediate = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: 'CN=Test WWDR Intermediate, O=Test',
    issuer: root.cert.subject,
    notBefore: new Date(Date.now() - DAY),
    notAfter: new Date(Date.now() + 1000 * DAY),
    publicKey: intKeys.publicKey,
    signingKey: root.keys.privateKey,
    signingAlgorithm: SIG,
    extensions: intExt,
  });

  const leafKeys = await genKeys();
  const leafExt: x509.Extension[] = [new x509.BasicConstraintsExtension(false)];
  if (opts.leafOid ?? true) leafExt.push(new x509.Extension(APPLE_RECEIPT_SIGNING_OID, false, DER_NULL));
  const leaf = await x509.X509CertificateGenerator.create({
    serialNumber: '03',
    subject: 'CN=Test Prod ECC Mac App Store and iTunes Store Receipt Signing, O=Test',
    issuer: intermediate.subject,
    notBefore: new Date(Date.now() - 2 * DAY),
    notAfter: opts.leafNotAfter ?? new Date(Date.now() + 365 * DAY),
    publicKey: leafKeys.publicKey,
    signingKey: intKeys.privateKey,
    signingAlgorithm: SIG,
    extensions: leafExt,
  });

  const b64 = (c: x509.X509Certificate) => Buffer.from(c.rawData).toString('base64');
  const x5c = [b64(leaf), b64(intermediate), b64(root.cert)];
  return {
    root: new NodeX509(Buffer.from(root.cert.rawData)),
    rootPem: root.cert.toString('pem'),
    x5c,
    leafKey: leafKeys.privateKey,
    sign: (payload, o = {}) =>
      new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
        .setProtectedHeader({ alg: 'ES256', x5c: o.x5c ?? x5c })
        .sign(o.key ?? leafKeys.privateKey),
  };
}
