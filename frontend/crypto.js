// ==========================================================
// Web Crypto API: AES-256-GCM End-to-End Encryption Engine
// ==========================================================

const DEFAULT_CRYPTO_SECRET = "jwt-python-test-secure-aes256gcm-key";

/**
 * Convierte un ArrayBuffer o Uint8Array a Base64 URL-Safe sin padding
 */
function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Convierte un string Base64 / Base64URL a Uint8Array
 */
function base64UrlToUint8Array(base64Url) {
  let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Deriva una clave CryptoKey AES-256 a partir de un secreto usando SHA-256
 */
let _cachedCryptoKey = null;
let _cachedSecret = null;

async function getAesCryptoKey(secret = DEFAULT_CRYPTO_SECRET) {
  if (_cachedCryptoKey && _cachedSecret === secret) {
    return _cachedCryptoKey;
  }
  const enc = new TextEncoder();
  const secretBytes = enc.encode(secret);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', secretBytes);
  
  _cachedCryptoKey = await window.crypto.subtle.importKey(
    'raw',
    hashBuffer,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
  _cachedSecret = secret;
  return _cachedCryptoKey;
}

/**
 * Cifra datos con AES-256-GCM usando Web Crypto API
 * Formato del resultado: Base64URL([12 bytes IV] + [Ciphertext] + [16 bytes Tag])
 */
async function encryptPayload(data, secret = DEFAULT_CRYPTO_SECRET) {
  const key = await getAesCryptoKey(secret);
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit nonce
  const enc = new TextEncoder();
  const rawString = typeof data === 'string' ? data : JSON.stringify(data);
  const encodedData = enc.encode(rawString);

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128 // 16 bytes tag
    },
    key,
    encodedData
  );

  // Combinar IV + Ciphertext (que ya incluye el tag de 16 bytes al final en Web Crypto)
  const combined = new Uint8Array(iv.byteLength + encryptedBuffer.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encryptedBuffer), iv.byteLength);

  return bufferToBase64Url(combined);
}

/**
 * Descifra datos cifrados con AES-256-GCM
 */
async function decryptPayload(cipherBase64, secret = DEFAULT_CRYPTO_SECRET) {
  if (!cipherBase64 || typeof cipherBase64 !== 'string') {
    throw new Error('Payload cifrado inválido');
  }

  const key = await getAesCryptoKey(secret);
  const rawBytes = base64UrlToUint8Array(cipherBase64.trim());

  if (rawBytes.length < 28) {
    throw new Error('El payload cifrado es demasiado corto o está corrupto');
  }

  const iv = rawBytes.slice(0, 12);
  const ciphertextWithTag = rawBytes.slice(12);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128
    },
    key,
    ciphertextWithTag
  );

  const dec = new TextDecoder();
  const decryptedText = dec.decode(decryptedBuffer);

  try {
    return JSON.parse(decryptedText);
  } catch {
    return decryptedText;
  }
}

/**
 * Cliente HTTP Seguro: Realiza peticiones HTTP cifradas de extremo a extremo
 */
async function secureFetch(url, options = {}) {
  const opts = { ...options };
  opts.headers = { ...opts.headers };

  let isEncryptedRequest = false;
  let rawBodyData = null;

  if (opts.body) {
    if (typeof opts.body === 'string') {
      try {
        rawBodyData = JSON.parse(opts.body);
      } catch {
        rawBodyData = opts.body;
      }
    } else {
      rawBodyData = opts.body;
    }

    // Cifrar cuerpo con AES-256-GCM
    const encryptedString = await encryptPayload(rawBodyData);
    opts.body = JSON.stringify({ encrypted_payload: encryptedString });
    opts.headers['Content-Type'] = 'application/json';
    opts.headers['X-Encrypted-Payload'] = 'true';
    isEncryptedRequest = true;

    // Registrar evento de cifrado para el inspector
    if (window.onCryptoActivity) {
      window.onCryptoActivity({
        type: 'REQUEST_ENCRYPTED',
        url: url,
        method: opts.method || 'GET',
        plainLength: JSON.stringify(rawBodyData).length,
        cipherLength: encryptedString.length
      });
    }
  }

  const response = await fetch(url, opts);
  let responseData;
  const contentType = response.headers.get('content-type') || '';

  if (contentType.includes('application/json')) {
    responseData = await response.json();
    
    // Si la respuesta viene cifrada desde el backend
    if (responseData && responseData.encrypted && responseData.encrypted_payload) {
      const decrypted = await decryptPayload(responseData.encrypted_payload);
      
      if (window.onCryptoActivity) {
        window.onCryptoActivity({
          type: 'RESPONSE_DECRYPTED',
          url: url,
          status: response.status,
          cipherLength: responseData.encrypted_payload.length,
          plainData: decrypted
        });
      }

      return {
        ok: response.ok,
        status: response.status,
        data: decrypted,
        isEncrypted: true,
        rawEncryptedPayload: responseData.encrypted_payload
      };
    }
  } else {
    responseData = await response.text();
  }

  return {
    ok: response.ok,
    status: response.status,
    data: responseData,
    isEncrypted: false
  };
}

const CryptoEngine = {
  encryptPayload,
  decryptPayload,
  secureFetch,
  bufferToBase64Url,
  base64UrlToUint8Array
};

if (typeof window !== 'undefined') {
  window.CryptoEngine = CryptoEngine;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CryptoEngine;
}
