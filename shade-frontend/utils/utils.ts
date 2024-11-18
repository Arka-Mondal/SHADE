import * as crypto from 'crypto';

export const generateKeyPair = async () => {
  try {
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
  } catch (error) {
    console.error('Error generating key pair:', error);
    throw error; // Rethrow the error after logging
  }
}

export const deriveSharedSecret = async (privateKeyPem: string, publicKeyPem: string) => {
  try {
    console.log("Hello from Derive Shared Secret");
    // Convert PEM to ArrayBuffer
    const privateKeyBase64 = privateKeyPem.replace(
      /(-----(BEGIN|END) PRIVATE KEY-----|\n)/g,
      ''
    );
    const publicKeyBase64 = publicKeyPem.replace(
      /(-----(BEGIN|END) PUBLIC KEY-----|\n)/g,
      ''
    );

    const privateKeyBuffer = Uint8Array.from(atob(privateKeyBase64), c => c.charCodeAt(0));
    const publicKeyBuffer = Uint8Array.from(atob(publicKeyBase64), c => c.charCodeAt(0));

    // Import keys
    const privateKey = await window.crypto.subtle.importKey(
      'pkcs8',
      privateKeyBuffer,
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      false,
      ['deriveBits']
    );

    const publicKey = await window.crypto.subtle.importKey(
      'spki',
      publicKeyBuffer,
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      false,
      []
    );

    // Derive shared secret
    const sharedSecretBuffer = await window.crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: publicKey
      },
      privateKey,
      256
    );

    return new Uint8Array(sharedSecretBuffer);
  } catch (error) {
    console.error('Error deriving shared secret:', error);
    throw error;
  }
};

export const deriveKey = async (sharedSecret1: Buffer, sharedSecret2: Buffer, providedSalt: Buffer) => {
  try {
    if (!sharedSecret1 || !sharedSecret2) {
      throw new Error('shared secret not computed');
    }

    console.log('Shared Secret 1:', sharedSecret1);
    console.log('Shared Secret 2:', sharedSecret2);
    
    let sharedSecret = new Uint8Array(sharedSecret1.length + sharedSecret2.length);
    sharedSecret.set(sharedSecret1);
    sharedSecret.set(sharedSecret2, sharedSecret1.length);

    const hashAlgorithm = 'sha256';  // SHA-256 hash length in bytes
    const hashLength = crypto.createHash(hashAlgorithm).digest().length;

    let salt = providedSalt;
    if (!salt) {
      salt = crypto.randomBytes(hashLength);
    }

    console.log('Salt:', salt);

    const info = Buffer.from('SHADE Enc-Dec Key');

    const prk = crypto.createHmac(hashAlgorithm, salt)
        .update(sharedSecret)
        .digest();

    console.log('PRK:', prk);

    const hmac = crypto.createHmac(hashAlgorithm, prk);
    const infoBuffer = Buffer.concat([
        info,
        Buffer.from([0x01])
    ]);
    hmac.update(infoBuffer);
    const key = hmac.digest().slice(0, hashLength);

    console.log('Derived Key:', key);

    return { key, salt };
  } catch (error) {
    console.error('Error deriving key:', error);
    throw error; // Rethrow the error after logging
  }
}

export const decrypt = async(key: Buffer, ciphertextWithNonce: Buffer) => {
  try {
    if (!(key instanceof Buffer) || !(ciphertextWithNonce instanceof Buffer)) {
      throw new Error('Key and cipher-text must be a Buffer');
    }

    console.log('Key for Decryption:', key);
    console.log('Ciphertext with Nonce:', ciphertextWithNonce);

    const nonce = ciphertextWithNonce.subarray(0, 12);
    const authTag = ciphertextWithNonce.subarray(ciphertextWithNonce.length - 16);
    const ciphertext = ciphertextWithNonce.subarray(12, ciphertextWithNonce.length - 16);

    console.log('Nonce:', nonce);
    console.log('Auth Tag:', authTag);
    console.log('Ciphertext:', ciphertext);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAAD(Buffer.alloc(0)); // Empty AAD to match Go - backend
    decipher.setAuthTag(authTag);

    const decryptedData = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);

    console.log('Decrypted Data:', decryptedData);

    return decryptedData;
  } catch (error) {
    console.error('Error during decryption:', error);
    throw error; // Rethrow the error after logging
  }
}

const universalBase64 = {
  encode: (str: string) => {
      return Buffer.from(str).toString('base64');
  },

  decode: (str: string) => {
    try {
      const decoded = window.atob(str);
      
      // Convert to bytes
      const bytes = new Uint8Array(decoded.length);
      for (let i = 0; i < decoded.length; i++) {
        bytes[i] = decoded.charCodeAt(i);
      }
      
      // Convert bytes to string using TextDecoder

      return new TextDecoder('utf-8').decode(bytes);
    } catch (error) {
      throw new Error('Failed to decode base64 string: ' + error);
    }
  }
};

export const jsonenc = (pemKey: string) => {
  const encoded = universalBase64.encode(pemKey);
  return encoded
}

export const jsondec = (encoded: string) => {
  const decoded = universalBase64.decode(encoded);
  return decoded
}

export const jsonBitArrEncode = (bytes: Uint8Array): string => {
  // console.log('salt encoding');

  // Convert the byte array to a string of characters (binary string)
  let binaryString = '';
  for (let i = 0; i < bytes.length; i++) {
    binaryString += String.fromCharCode(bytes[i]);
  }

  // Return the Base64 encoded version of the binary string
  return window.btoa(binaryString);
}

export const jsonBitArrDecode = (salt: string)=> {
  console.log('salt decoding')
  const decoded = window.atob(salt);
  
  // Create a Uint8Array to hold the bytes
  const bytes = new Uint8Array(decoded.length);
  
  // Populate the Uint8Array with the character codes from the binary string
  for (let i = 0; i < decoded.length; i++) {
    bytes[i] = decoded.charCodeAt(i);
  }

  // Return the byte array
  return bytes;
}

export async function sign(privateKeyPem: string, data: Uint8Array | Buffer): Promise<Uint8Array> {
  // Import the private key
  const privateKey = await importPrivateKey(privateKeyPem);

  // Convert data to Uint8Array if it's a Buffer
  const dataArray = data instanceof Buffer ? new Uint8Array(data) : data;

  // Create a hash of the data
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', dataArray);

  // Sign the hash
  const signature = await window.crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' },
    },
    privateKey,
    dataArray // Sign the original data, not the hash
  );

  return new Uint8Array(signature);
}

export async function verify(publicKeyPem: string, data: Uint8Array | Buffer, signature: Uint8Array): Promise<boolean> {
  try {
    const publicKey = await importPublicKey(publicKeyPem);
    
    // Convert data to Uint8Array if it's a Buffer
    const dataArray = data instanceof Buffer ? new Uint8Array(data) : data;

    // Verify the signature
    return await window.crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      publicKey,
      signature,
      dataArray // Verify against the original data, not a hash
    );
  } catch (error) {
    console.error('Verification error:', error);
    return false;
  }
}

// Helper function to import the private key in PEM format to a CryptoKey
async function importPrivateKey(pem: string): Promise<CryptoKey> {
  // Remove the PEM header and footer, and decode the base64 content
  const binaryDerString = window.atob(pem.replace('-----BEGIN PRIVATE KEY-----', '').replace('-----END PRIVATE KEY-----', '').trim());
  const binaryDer = str2ab(binaryDerString);

  // Import the private key into a CryptoKey object
  return await window.crypto.subtle.importKey(
      "pkcs8", // Private key format
      binaryDer, // The private key in binary format
      {
          name: "ECDSA", // ECDSA with P-256 curve
          namedCurve: "P-256", // The P-256 curve
      },
      false, // The key is not extractable
      ["sign"] // The key can only be used for signing
  );
}

async function importPublicKey(pem: string): Promise<CryptoKey> {
  // Remove the PEM header and footer, and decode the base64 content
  const binaryDerString = window.atob(pem.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').trim());
  const binaryDer = str2ab(binaryDerString);

  // Import the public key into a CryptoKey object
  return await window.crypto.subtle.importKey(
      "spki", // Public key format
      binaryDer, // The public key in binary format
      {
          name: "ECDSA", // ECDSA with P-256 curve
          namedCurve: "P-256", // The P-256 curve
      },
      false, // The key is not extractable
      ["verify"] // The key can only be used for verification
  );
}

function derToRaw(derSignature: Buffer) {
  // DER format:
  // 30 xx             - sequence tag and length
  //    02 xx R        - integer tag, length, and R value
  //    02 xx S        - integer tag, length, and S value
  
  let offset = 2; // Skip sequence tag and length
  
  // Get R
  const rLength = derSignature[offset + 1]; // Get length of R
  offset += 2; // Skip integer tag and length

  let r = derSignature.slice(offset, offset + rLength);
  // Ensure R is 32 bytes, removing padding if necessary

  if (r[0] === 0)
      r = r.slice(1);

  if (r.length < 32)
      r = Buffer.concat([Buffer.alloc(32 - r.length, 0), r]);
  
  offset += rLength; // Skip R value
  
  // Get S
  const sLength = derSignature[offset + 1]; // Get length of S
  offset += 2; // Skip integer tag and length
  let s = derSignature.slice(offset, offset + sLength);

  // Ensure S is 32 bytes, removing padding if necessary
  if (s[0] === 0)
      s = s.slice(1);

  if (s.length < 32)
      s = Buffer.concat([Buffer.alloc(32 - s.length, 0), s]);
  
  // Concatenate R and S
  return Buffer.concat([r, s]);
}

function str2ab(str: string): ArrayBuffer {
  const buf = new ArrayBuffer(str.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < str.length; i++) {
      view[i] = str.charCodeAt(i);
  }
  return buf;
}