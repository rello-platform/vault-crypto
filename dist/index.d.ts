declare const DEFAULT_KEY_ID = "v2-vault-secret";
declare class VaultCryptoError extends Error {
    /** Machine-readable failure category for callers that branch on cause. */
    readonly code: "CONFIG" | "FORMAT" | "AUTH" | "LEGACY_FORMAT" | "LEGACY_AUTH";
    constructor(code: VaultCryptoError["code"], message: string);
}
interface VaultCrypto {
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
interface CreateVaultCryptoOptions {
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
declare function createVaultCrypto(options: CreateVaultCryptoOptions): VaultCrypto;
/**
 * A bare decrypt function — lets rotateKey work across legacy formats too:
 * bind the legacy secret yourself, e.g.
 * `(ct) => LEGACY_DECODERS["harvest-home"](ct, legacySecret)`.
 */
type RotateDecryptFn = (ciphertext: string) => string;
interface RotateKeyResult {
    /** The re-encrypted canonical ciphertext under the to-key instance. */
    ciphertext: string;
    /** The to-key instance's keyId — persist alongside the ciphertext (same transactional write). */
    keyId: string;
}
/**
 * Rotate a stored ciphertext from one key to another:
 * decrypt with `fromCrypto` → re-encrypt with `toCrypto` → return
 * `{ ciphertext, keyId }`. This function is PURE — it never touches storage;
 * the caller updates the row transactionally (ciphertext + keyId together).
 *
 * `fromCrypto` accepts either a VaultCrypto instance (same-format secret
 * rotation) or a bare decrypt function (legacy-format migrations via
 * LEGACY_DECODERS — close over the legacy secret yourself).
 *
 * Decrypt failures propagate untouched (VaultCryptoError AUTH / FORMAT /
 * LEGACY_AUTH / LEGACY_FORMAT) so callers can branch on `code` — a
 * wrong-from-key rotation THROWS, it never silently re-encrypts garbage.
 */
declare function rotateKey(ciphertext: string, fromCrypto: Pick<VaultCrypto, "decrypt"> | RotateDecryptFn, toCrypto: Pick<VaultCrypto, "encrypt" | "keyId">): RotateKeyResult;
type LegacyDecoder = (encryptedValue: string, secret: string) => string;
/** Canonical spoke slugs (per @rello-platform/slugs APP_SLUGS). */
type LegacySpokeSlug = "pathfinder-pro" | "harvest-home" | "home-ready" | "the-drumbeat" | "open-house-hub" | "newsletter-studio" | "market-intel";
/**
 * Per-spoke legacy decoders, keyed by canonical slug. Each spoke's one-shot
 * migration: read row → LEGACY_DECODERS[slug](encryptedValue, legacySecret)
 * → createVaultCrypto({ secret: newSecret }).encrypt(plaintext) → write
 * back with kmsKeyId = instance.keyId.
 */
declare const LEGACY_DECODERS: Readonly<Record<LegacySpokeSlug, LegacyDecoder>>;

export { type CreateVaultCryptoOptions, DEFAULT_KEY_ID, LEGACY_DECODERS, type LegacyDecoder, type LegacySpokeSlug, type RotateDecryptFn, type RotateKeyResult, type VaultCrypto, VaultCryptoError, createVaultCrypto, rotateKey };
