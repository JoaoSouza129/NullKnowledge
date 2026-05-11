/**
 * SecureCrypto - Zero-Knowledge Encryption Library
 * Implementação de cifra AES-256-GCM no browser
 */

const SecureCrypto = {
  /**
   * Gera uma chave aleatória de 256 bits (32 bytes)
   * @returns {Promise<string>} Chave em Base64
   */
  async generateKey() {
    const key = await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, // extractable
      ['encrypt', 'decrypt']
    );
    
    const exported = await window.crypto.subtle.exportKey('raw', key);
    return this._arrayBufferToBase64(exported);
  },

  /**
   * Cifra um texto usando AES-256-GCM
   * @param {string} text - Texto a cifrar
   * @param {string} keyB64 - Chave em Base64
   * @returns {Promise<string>} Ciphertext em JSON Base64 (contém iv + ciphertext + tag)
   */
  async encryptText(text, keyB64) {
    // Importa a chave
    const keyBuffer = this._base64ToArrayBuffer(keyB64);
    const key = await window.crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-GCM', length: 256 },
      false, // not extractable after import
      ['encrypt']
    );

    // Gera um IV aleatório (12 bytes para GCM)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // Cifra o texto
    const encoder = new TextEncoder();
    const plaintext = encoder.encode(text);

    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      plaintext
    );

    // Combina IV + ciphertext e retorna em Base64
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);

    return this._arrayBufferToBase64(combined.buffer);
  },

  /**
   * Decifra um texto usando AES-256-GCM
   * @param {string} ciphertextB64 - Ciphertext em Base64 (iv + ciphertext + tag)
   * @param {string} keyB64 - Chave em Base64
   * @returns {Promise<string>} Texto decifrado
   */
  async decryptText(ciphertextB64, keyB64) {
    // Importa a chave
    const keyBuffer = this._base64ToArrayBuffer(keyB64);
    const key = await window.crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // Extrai IV (primeiros 12 bytes) e ciphertext
    const combined = this._base64ToArrayBuffer(ciphertextB64);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    // Decifra
    const plaintext = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      ciphertext
    );

    // Converte para string
    const decoder = new TextDecoder();
    return decoder.decode(plaintext);
  },

  /**
   * Converte ArrayBuffer para Base64
   * @private
   */
  _arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  },

  /**
   * Converte Base64 para ArrayBuffer
   * @private
   */
  _base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
};

globalThis.SecureCrypto = SecureCrypto;
