export default async function generateKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify']
  );

  const publicKey = await window.crypto.subtle.exportKey(
    'spki',
    keyPair.publicKey
  );

  const privateKey = await window.crypto.subtle.exportKey(
    'pkcs8',
    keyPair.privateKey
  );

  const publicKeyBase64 = btoa(Array.from(new Uint8Array(publicKey), byte => String.fromCharCode(byte)).join(''));
  const privateKeyBase64 = btoa(Array.from(new Uint8Array(privateKey), byte => String.fromCharCode(byte)).join(''));

  return {
    publicKey: `-----BEGIN PUBLIC KEY-----\n${publicKeyBase64}\n-----END PUBLIC KEY-----`,
    privateKey: `-----BEGIN PRIVATE KEY-----\n${privateKeyBase64}\n-----END PRIVATE KEY-----`
  };
}
