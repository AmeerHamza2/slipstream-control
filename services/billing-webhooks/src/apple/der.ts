/**
 * Just enough DER to list the extension OIDs of an X.509 certificate. node:crypto's
 * X509Certificate verifies signatures but does not expose arbitrary extensions, and the
 * Apple marker OIDs are the one thing we need from them.
 *
 *   Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
 *   TBSCertificate ::= SEQUENCE { [0] version, serial, sig, issuer, validity, subject,
 *                                 spki, [1]?, [2]?, [3] EXPLICIT Extensions }
 *   Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
 */
interface Tlv {
  tag: number;
  start: number; // first content byte
  end: number; // one past the last content byte
}

function readTlv(buf: Buffer, offset: number, limit: number): Tlv {
  if (offset + 2 > limit) throw new Error('DER: truncated');
  const tag = buf[offset]!;
  let len = buf[offset + 1]!;
  let p = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > limit) throw new Error('DER: bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p + i]!;
    p += n;
  }
  if (p + len > limit) throw new Error('DER: length exceeds buffer');
  return { tag, start: p, end: p + len };
}

function children(buf: Buffer, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let p = parent.start; p < parent.end; ) {
    const t = readTlv(buf, p, parent.end);
    out.push(t);
    p = t.end;
  }
  return out;
}

function decodeOid(bytes: Buffer): string {
  const first = bytes[0]!;
  const parts = [Math.floor(first / 40), first % 40];
  let v = 0;
  for (let i = 1; i < bytes.length; i++) {
    v = v * 128 + (bytes[i]! & 0x7f);
    if (!(bytes[i]! & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}

const SEQUENCE = 0x30;
const OID = 0x06;
const EXTENSIONS_TAG = 0xa3;

/** OIDs of every extension present in a DER-encoded certificate. */
export function extensionOids(der: Buffer): string[] {
  const cert = readTlv(der, 0, der.length);
  if (cert.tag !== SEQUENCE) throw new Error('DER: certificate is not a SEQUENCE');
  const tbs = children(der, cert)[0];
  if (!tbs || tbs.tag !== SEQUENCE) throw new Error('DER: missing tbsCertificate');
  const extWrapper = children(der, tbs).find((t) => t.tag === EXTENSIONS_TAG);
  if (!extWrapper) return [];
  const extSeq = children(der, extWrapper)[0];
  if (!extSeq || extSeq.tag !== SEQUENCE) throw new Error('DER: malformed extensions');
  return children(der, extSeq).map((ext) => {
    const oid = children(der, ext)[0];
    if (!oid || oid.tag !== OID) throw new Error('DER: malformed extension');
    return decodeOid(der.subarray(oid.start, oid.end));
  });
}
