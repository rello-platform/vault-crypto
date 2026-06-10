// src/index.ts
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  pbkdf2Sync,
  randomBytes,
  scryptSync
} from "crypto";
var FORMAT_VERSION = "v2";
var DEFAULT_KEY_ID = "v2-vault-secret";
var CANONICAL_SCRYPT_SALT = "rello-platform.vault-crypto.v2";
var ALGORITHM = "aes-256-gcm";
var IV_LENGTH = 12;
var AUTH_TAG_LENGTH = 16;
var KEY_LENGTH = 32;
var MIN_SECRET_LENGTH = 32;
var VaultCryptoError = class extends Error {
  constructor(code, message) {
    super(`[vault-crypto:${code}] ${message}`);
    this.name = "VaultCryptoError";
    this.code = code;
  }
};
function createVaultCrypto(options) {
  const { secret, keyId = DEFAULT_KEY_ID } = options ?? {};
  if (typeof secret !== "string" || secret.length === 0) {
    throw new VaultCryptoError(
      "CONFIG",
      "createVaultCrypto requires a non-empty `secret` string (inject the BILLING_VAULT_KEY_DERIVATION_SECRET env VALUE \u2014 this lib never reads process.env)."
    );
  }
  if (secret.length < MIN_SECRET_LENGTH) {
    throw new VaultCryptoError(
      "CONFIG",
      `createVaultCrypto \`secret\` must be >= ${MIN_SECRET_LENGTH} chars (got ${secret.length}).`
    );
  }
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw new VaultCryptoError("CONFIG", "createVaultCrypto `keyId` must be a non-empty string when provided.");
  }
  let cachedKey = null;
  function getKey() {
    if (cachedKey === null) {
      cachedKey = scryptSync(secret, CANONICAL_SCRYPT_SALT, KEY_LENGTH);
    }
    return cachedKey;
  }
  function encrypt(plaintext) {
    if (typeof plaintext !== "string" || plaintext.length === 0) {
      throw new VaultCryptoError("FORMAT", "encrypt requires a non-empty plaintext string.");
    }
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, getKey(), iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return [
      FORMAT_VERSION,
      iv.toString("base64"),
      ciphertext.toString("base64"),
      authTag.toString("base64")
    ].join(":");
  }
  function decrypt(value) {
    if (typeof value !== "string" || value.length === 0) {
      throw new VaultCryptoError("FORMAT", "decrypt requires a non-empty ciphertext string.");
    }
    const parts = value.split(":");
    if (parts.length !== 4) {
      throw new VaultCryptoError(
        "FORMAT",
        `Malformed envelope \u2014 expected 4 colon-separated segments (v2:<iv>:<ciphertext>:<authTag>), got ${parts.length}. A legacy-format row must go through LEGACY_DECODERS during migration.`
      );
    }
    const [version, ivB64, ciphertextB64, authTagB64] = parts;
    if (version !== FORMAT_VERSION) {
      throw new VaultCryptoError(
        "FORMAT",
        `Unsupported envelope version "${version}" (expected "${FORMAT_VERSION}"). A legacy-format row must go through LEGACY_DECODERS during migration.`
      );
    }
    const iv = Buffer.from(ivB64, "base64");
    const ciphertext = Buffer.from(ciphertextB64, "base64");
    const authTag = Buffer.from(authTagB64, "base64");
    if (iv.length !== IV_LENGTH) {
      throw new VaultCryptoError("FORMAT", `IV segment decodes to ${iv.length} bytes (expected ${IV_LENGTH}).`);
    }
    if (authTag.length !== AUTH_TAG_LENGTH) {
      throw new VaultCryptoError(
        "FORMAT",
        `authTag segment decodes to ${authTag.length} bytes (expected ${AUTH_TAG_LENGTH}).`
      );
    }
    if (ciphertext.length === 0) {
      throw new VaultCryptoError("FORMAT", "ciphertext segment is empty.");
    }
    try {
      const decipher = createDecipheriv(ALGORITHM, getKey(), iv);
      decipher.setAuthTag(authTag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
    } catch (err) {
      throw new VaultCryptoError(
        "AUTH",
        `GCM authentication failed (tampered ciphertext or wrong key/secret): ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
  return { encrypt, decrypt, keyId };
}
function requireSecret(secret, who) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new VaultCryptoError("CONFIG", `${who}: legacy decode requires the non-empty legacy secret value (the spoke's former RELLO_APP_SECRET).`);
  }
  return secret;
}
function sha256Key(secret) {
  return createHash("sha256").update(secret).digest();
}
function gcmDecrypt(key, iv, ciphertext, authTag, who) {
  try {
    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch (err) {
    throw new VaultCryptoError(
      "LEGACY_AUTH",
      `${who}: GCM authentication failed (tampered row or wrong legacy secret): ${err instanceof Error ? err.message : String(err)}`
    );
  }
}
function decodePathfinderPro(encryptedValue, secret) {
  const parts = encryptedValue.split(":");
  if (parts.length !== 3) {
    throw new VaultCryptoError(
      "LEGACY_FORMAT",
      `pathfinder-pro: malformed payload \u2014 expected 3 colon-separated hex segments (iv:authTag:ciphertext), got ${parts.length}.`
    );
  }
  const [ivHex, authTagHex, ciphertextHex] = parts;
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const ciphertext = Buffer.from(ciphertextHex, "hex");
  if (iv.length !== IV_LENGTH || authTag.length !== AUTH_TAG_LENGTH) {
    throw new VaultCryptoError("LEGACY_FORMAT", "pathfinder-pro: IV or authTag length mismatch.");
  }
  return gcmDecrypt(sha256Key(requireSecret(secret, "pathfinder-pro")), iv, ciphertext, authTag, "pathfinder-pro");
}
function decodeHarvestHome(encryptedValue, secret) {
  requireSecret(secret, "harvest-home");
  const blob = Buffer.from(encryptedValue, "base64");
  if (blob.length < IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new VaultCryptoError("LEGACY_FORMAT", "harvest-home: envelope too short to contain IV + auth tag.");
  }
  const iv = blob.subarray(0, IV_LENGTH);
  const authTag = blob.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = blob.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const key = pbkdf2Sync(secret, "rello-spoke-vault-v1", 1e5, 32, "sha256");
  return gcmDecrypt(key, iv, ciphertext, authTag, "harvest-home");
}
function decodeHomeReady(encryptedValue, secret) {
  requireSecret(secret, "home-ready");
  const envelope = Buffer.from(encryptedValue, "base64");
  if (envelope.length < IV_LENGTH + AUTH_TAG_LENGTH + 1) {
    throw new VaultCryptoError("LEGACY_FORMAT", "home-ready: envelope too short.");
  }
  const iv = envelope.subarray(0, IV_LENGTH);
  const authTag = envelope.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = envelope.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  return gcmDecrypt(sha256Key(secret), iv, ciphertext, authTag, "home-ready");
}
function decodeTheDrumbeat(encryptedValue, secret) {
  requireSecret(secret, "the-drumbeat");
  const buf = Buffer.from(encryptedValue, "base64");
  if (buf.length < IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new VaultCryptoError("LEGACY_FORMAT", "the-drumbeat: invalid vault envelope: too short.");
  }
  const iv = buf.subarray(0, IV_LENGTH);
  const authTag = buf.subarray(buf.length - AUTH_TAG_LENGTH);
  const ciphertext = buf.subarray(IV_LENGTH, buf.length - AUTH_TAG_LENGTH);
  return gcmDecrypt(sha256Key(secret), iv, ciphertext, authTag, "the-drumbeat");
}
function decodeOpenHouseHub(encryptedValue, secret) {
  requireSecret(secret, "open-house-hub");
  const envelope = Buffer.from(encryptedValue, "base64");
  if (envelope.length < IV_LENGTH + AUTH_TAG_LENGTH + 1) {
    throw new VaultCryptoError("LEGACY_FORMAT", "open-house-hub: encrypted envelope too short.");
  }
  const iv = envelope.subarray(0, IV_LENGTH);
  const authTag = envelope.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = envelope.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  return gcmDecrypt(sha256Key(secret), iv, ciphertext, authTag, "open-house-hub");
}
function decodeNewsletterStudio(encryptedValue, secret) {
  requireSecret(secret, "newsletter-studio");
  const packed = Buffer.from(encryptedValue, "base64");
  if (packed.length < IV_LENGTH + AUTH_TAG_LENGTH + 1) {
    throw new VaultCryptoError(
      "LEGACY_FORMAT",
      "newsletter-studio: packed payload too short to contain iv+tag+ciphertext."
    );
  }
  const iv = packed.subarray(0, IV_LENGTH);
  const authTag = packed.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = packed.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const key = scryptSync(secret, Buffer.from("rello-platform-spoke-vault-v1"), KEY_LENGTH);
  return gcmDecrypt(key, iv, ciphertext, authTag, "newsletter-studio");
}
function decodeMarketIntel(encryptedValue, secret) {
  requireSecret(secret, "market-intel");
  const parts = encryptedValue.split(":");
  if (parts.length !== 4) {
    throw new VaultCryptoError(
      "LEGACY_FORMAT",
      `market-intel: malformed encryptedValue \u2014 expected 4 colon-separated parts, got ${parts.length}.`
    );
  }
  const [keyId, ivHex, tagHex, ciphertextHex] = parts;
  if (keyId !== "v1-app-secret") {
    throw new VaultCryptoError(
      "LEGACY_FORMAT",
      `market-intel: unknown kmsKeyId in encryptedValue: ${keyId} (expected v1-app-secret).`
    );
  }
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(tagHex, "hex");
  const ciphertext = Buffer.from(ciphertextHex, "hex");
  const key = scryptSync(secret, "rello-platform.spoke-api-key-vault.v1", KEY_LENGTH);
  return gcmDecrypt(key, iv, ciphertext, authTag, "market-intel");
}
var LEGACY_DECODERS = Object.freeze({
  "pathfinder-pro": decodePathfinderPro,
  "harvest-home": decodeHarvestHome,
  "home-ready": decodeHomeReady,
  "the-drumbeat": decodeTheDrumbeat,
  "open-house-hub": decodeOpenHouseHub,
  "newsletter-studio": decodeNewsletterStudio,
  "market-intel": decodeMarketIntel
});
export {
  DEFAULT_KEY_ID,
  LEGACY_DECODERS,
  VaultCryptoError,
  createVaultCrypto
};
//# sourceMappingURL=index.js.map