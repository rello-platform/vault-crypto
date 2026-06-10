import {
  createCipheriv,
  createDecipheriv,
  createHash,
  pbkdf2Sync,
  randomBytes,
  scryptSync,
} from "node:crypto";

/**
 * @rello-platform/vault-crypto — canonical SpokeApiKeyVault encryption.
 *
 * Q7 lock (CROSS-REPO-WALK-DECISIONS-260609 §Q7 ¶3): the 7 spoke
 * vault-encryption files were NOT copies — 3 KDFs (SHA-256 ×4, PBKDF2-100k
 * in Harvest Home, scrypt in Newsletter Studio / MarketIntel), 2+ encoding
 * formats, and The Drumbeat uniquely placed the GCM authTag last. This
 * package is the ONE canonical implementation that replaces all 7:
 *
 *   - KDF:       scrypt (N=16384, r=8, p=1 — node defaults), fixed salt
 *   - Cipher:    AES-256-GCM, 12-byte IV, 16-byte authTag
 *   - Encoding:  `v2:<iv>:<ciphertext>:<authTag>` — each segment base64,
 *                authTag LAST consistently
 *   - Secret:    config-injected VALUE (the spoke reads
 *                `BILLING_VAULT_KEY_DERIVATION_SECRET` lazily at call time
 *                and passes it in — this lib never reads process.env,
 *                mirroring @rello-platform/signals config-injection)
 *   - Version:   `keyId` parameter maps to the spokes' existing
 *                `kmsKeyId` column (default "v2-vault-secret")
 *
 * Legacy decoders for the migration one-shot re-encrypt live in
 * `LEGACY_DECODERS`, byte-faithful to each spoke's origin/main source.
 */

const FORMAT_VERSION = "v2";
export const DEFAULT_KEY_ID = "v2-vault-secret";
const CANONICAL_SCRYPT_SALT = "rello-platform.vault-crypto.v2";
const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const MIN_SECRET_LENGTH = 32;

export class VaultCryptoError extends Error {
  /** Machine-readable failure category for callers that branch on cause. */
  readonly code:
    | "CONFIG"
    | "FORMAT"
    | "AUTH"
    | "LEGACY_FORMAT"
    | "LEGACY_AUTH";

  constructor(code: VaultCryptoError["code"], message: string) {
    super(`[vault-crypto:${code}] ${message}`);
    this.name = "VaultCryptoError";
    this.code = code;
  }
}

export interface VaultCrypto {
  /** Encrypt plaintext → `v2:<iv>:<ciphertext>:<authTag>` (base64 segments). */
  encrypt(plaintext: string): string;
  /**
   * Decrypt a canonical `v2:` ciphertext. THROWS VaultCryptoError with
   * context on malformed input (FORMAT) or authTag/key mismatch (AUTH) —
   * never returns null/undefined on failure.
   */
  decrypt(ciphertext: string): string;
  /** The key-version identifier to persist in the spokes' `kmsKeyId` column. */
  readonly keyId: string;
}

export interface CreateVaultCryptoOptions {
  /**
   * The key-derivation secret VALUE (the caller reads
   * BILLING_VAULT_KEY_DERIVATION_SECRET from its own env, lazily at call
   * time, and injects it here). Must be >= 32 chars.
   */
  secret: string;
  /** kmsKeyId version marker. Default "v2-vault-secret". */
  keyId?: string;
}

/**
 * Create a vault-crypto instance bound to one secret + keyId.
 * Key derivation (scrypt) is memoized: it runs once on first use.
 */
export function createVaultCrypto(options: CreateVaultCryptoOptions): VaultCrypto {
  const { secret, keyId = DEFAULT_KEY_ID } = options ?? ({} as CreateVaultCryptoOptions);

  if (typeof secret !== "string" || secret.length === 0) {
    throw new VaultCryptoError(
      "CONFIG",
      "createVaultCrypto requires a non-empty `secret` string (inject the BILLING_VAULT_KEY_DERIVATION_SECRET env VALUE — this lib never reads process.env).",
    );
  }
  if (secret.length < MIN_SECRET_LENGTH) {
    throw new VaultCryptoError(
      "CONFIG",
      `createVaultCrypto \`secret\` must be >= ${MIN_SECRET_LENGTH} chars (got ${secret.length}).`,
    );
  }
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw new VaultCryptoError("CONFIG", "createVaultCrypto `keyId` must be a non-empty string when provided.");
  }

  // Memoized scrypt derivation — deterministic (fixed salt) so any process
  // restart decrypts rows written by a prior process; lazy so constructing
  // the instance at module load never pays the scrypt cost up front.
  let cachedKey: Buffer | null = null;
  function getKey(): Buffer {
    if (cachedKey === null) {
      cachedKey = scryptSync(secret, CANONICAL_SCRYPT_SALT, KEY_LENGTH);
    }
    return cachedKey;
  }

  function encrypt(plaintext: string): string {
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
      authTag.toString("base64"),
    ].join(":");
  }

  function decrypt(value: string): string {
    if (typeof value !== "string" || value.length === 0) {
      throw new VaultCryptoError("FORMAT", "decrypt requires a non-empty ciphertext string.");
    }
    const parts = value.split(":");
    if (parts.length !== 4) {
      throw new VaultCryptoError(
        "FORMAT",
        `Malformed envelope — expected 4 colon-separated segments (v2:<iv>:<ciphertext>:<authTag>), got ${parts.length}. A legacy-format row must go through LEGACY_DECODERS during migration.`,
      );
    }
    const [version, ivB64, ciphertextB64, authTagB64] = parts;
    if (version !== FORMAT_VERSION) {
      throw new VaultCryptoError(
        "FORMAT",
        `Unsupported envelope version "${version}" (expected "${FORMAT_VERSION}"). A legacy-format row must go through LEGACY_DECODERS during migration.`,
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
        `authTag segment decodes to ${authTag.length} bytes (expected ${AUTH_TAG_LENGTH}).`,
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
        `GCM authentication failed (tampered ciphertext or wrong key/secret): ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  return { encrypt, decrypt, keyId };
}

// ---------------------------------------------------------------------------
// LEGACY DECODERS — byte-faithful to each spoke's origin/main implementation.
// Each takes (encryptedValue, secret) and returns the plaintext, throwing
// VaultCryptoError (LEGACY_FORMAT / LEGACY_AUTH) with context on failure.
// Used ONLY for the one-shot re-encrypt migration of existing
// SpokeApiKeyVault rows; never for new writes.
// ---------------------------------------------------------------------------

export type LegacyDecoder = (encryptedValue: string, secret: string) => string;

/** Canonical spoke slugs (per @rello-platform/slugs APP_SLUGS). */
export type LegacySpokeSlug =
  | "pathfinder-pro"
  | "harvest-home"
  | "home-ready"
  | "the-drumbeat"
  | "open-house-hub"
  | "newsletter-studio"
  | "market-intel";

function requireSecret(secret: string, who: string): string {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new VaultCryptoError("CONFIG", `${who}: legacy decode requires the non-empty legacy secret value (the spoke's former RELLO_APP_SECRET).`);
  }
  return secret;
}

function sha256Key(secret: string): Buffer {
  // PFP / HomeReady / Drumbeat / OHH: createHash("sha256").update(secret).digest()
  return createHash("sha256").update(secret).digest();
}

function gcmDecrypt(key: Buffer, iv: Buffer, ciphertext: Buffer, authTag: Buffer, who: string): string {
  try {
    const decipher = createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch (err) {
    throw new VaultCryptoError(
      "LEGACY_AUTH",
      `${who}: GCM authentication failed (tampered row or wrong legacy secret): ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * PathfinderPro `src/lib/billing/vault-encryption.ts` (origin/main):
 * SHA-256(secret) key; payload is `<ivHex>:<authTagHex>:<ciphertextHex>`
 * (three colon-joined HEX segments, authTag SECOND).
 */
function decodePathfinderPro(encryptedValue: string, secret: string): string {
  const parts = encryptedValue.split(":");
  if (parts.length !== 3) {
    throw new VaultCryptoError(
      "LEGACY_FORMAT",
      `pathfinder-pro: malformed payload — expected 3 colon-separated hex segments (iv:authTag:ciphertext), got ${parts.length}.`,
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

/**
 * Harvest Home `src/lib/billing/vault-encryption.ts` (origin/main):
 * PBKDF2(secret, "rello-spoke-vault-v1", 100_000, 32, sha256) key;
 * envelope is base64(iv || authTag || ciphertext).
 */
function decodeHarvestHome(encryptedValue: string, secret: string): string {
  requireSecret(secret, "harvest-home");
  const blob = Buffer.from(encryptedValue, "base64");
  if (blob.length < IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new VaultCryptoError("LEGACY_FORMAT", "harvest-home: envelope too short to contain IV + auth tag.");
  }
  const iv = blob.subarray(0, IV_LENGTH);
  const authTag = blob.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = blob.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const key = pbkdf2Sync(secret, "rello-spoke-vault-v1", 100_000, 32, "sha256");
  return gcmDecrypt(key, iv, ciphertext, authTag, "harvest-home");
}

/**
 * HomeReady `src/lib/billing/vault-encryption.ts` (origin/main):
 * SHA-256(secret) key; envelope is base64(iv || authTag || ciphertext).
 */
function decodeHomeReady(encryptedValue: string, secret: string): string {
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

/**
 * The Drumbeat `src/lib/billing/vault/encryption.ts` (origin/main):
 * SHA-256(secret) key; envelope is base64(iv || ciphertext || authTag)
 * — UNIQUELY authTag LAST among the legacy spokes.
 */
function decodeTheDrumbeat(encryptedValue: string, secret: string): string {
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

/**
 * Open House Hub `src/lib/billing/vault-encryption.ts` (origin/main):
 * SHA-256(secret) key; envelope is base64(iv || authTag || ciphertext).
 * (Structurally identical to HomeReady; kept as its own entry so each
 * spoke's migration references its own decoder.)
 */
function decodeOpenHouseHub(encryptedValue: string, secret: string): string {
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

/**
 * Newsletter Studio `src/lib/billing/vault-encryption.ts` (origin/main):
 * scrypt(secret, Buffer.from("rello-platform-spoke-vault-v1"), 32) key;
 * envelope is base64(iv || authTag || ciphertext).
 */
function decodeNewsletterStudio(encryptedValue: string, secret: string): string {
  requireSecret(secret, "newsletter-studio");
  const packed = Buffer.from(encryptedValue, "base64");
  if (packed.length < IV_LENGTH + AUTH_TAG_LENGTH + 1) {
    throw new VaultCryptoError(
      "LEGACY_FORMAT",
      "newsletter-studio: packed payload too short to contain iv+tag+ciphertext.",
    );
  }
  const iv = packed.subarray(0, IV_LENGTH);
  const authTag = packed.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = packed.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const key = scryptSync(secret, Buffer.from("rello-platform-spoke-vault-v1"), KEY_LENGTH);
  return gcmDecrypt(key, iv, ciphertext, authTag, "newsletter-studio");
}

/**
 * MarketIntel `src/lib/billing/vault-encryption.ts` (origin/main):
 * scrypt(secret, "rello-platform.spoke-api-key-vault.v1", 32) key;
 * persisted format is `v1-app-secret:<ivHex>:<tagHex>:<ciphertextHex>`
 * (4 colon-separated parts, kmsKeyId prefix INSIDE the value).
 */
function decodeMarketIntel(encryptedValue: string, secret: string): string {
  requireSecret(secret, "market-intel");
  const parts = encryptedValue.split(":");
  if (parts.length !== 4) {
    throw new VaultCryptoError(
      "LEGACY_FORMAT",
      `market-intel: malformed encryptedValue — expected 4 colon-separated parts, got ${parts.length}.`,
    );
  }
  const [keyId, ivHex, tagHex, ciphertextHex] = parts;
  if (keyId !== "v1-app-secret") {
    throw new VaultCryptoError(
      "LEGACY_FORMAT",
      `market-intel: unknown kmsKeyId in encryptedValue: ${keyId} (expected v1-app-secret).`,
    );
  }
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(tagHex, "hex");
  const ciphertext = Buffer.from(ciphertextHex, "hex");
  const key = scryptSync(secret, "rello-platform.spoke-api-key-vault.v1", KEY_LENGTH);
  return gcmDecrypt(key, iv, ciphertext, authTag, "market-intel");
}

/**
 * Per-spoke legacy decoders, keyed by canonical slug. Each spoke's one-shot
 * migration: read row → LEGACY_DECODERS[slug](encryptedValue, legacySecret)
 * → createVaultCrypto({ secret: newSecret }).encrypt(plaintext) → write
 * back with kmsKeyId = instance.keyId.
 */
export const LEGACY_DECODERS: Readonly<Record<LegacySpokeSlug, LegacyDecoder>> = Object.freeze({
  "pathfinder-pro": decodePathfinderPro,
  "harvest-home": decodeHarvestHome,
  "home-ready": decodeHomeReady,
  "the-drumbeat": decodeTheDrumbeat,
  "open-house-hub": decodeOpenHouseHub,
  "newsletter-studio": decodeNewsletterStudio,
  "market-intel": decodeMarketIntel,
});
