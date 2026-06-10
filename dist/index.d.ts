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

export { type CreateVaultCryptoOptions, DEFAULT_KEY_ID, LEGACY_DECODERS, type LegacyDecoder, type LegacySpokeSlug, type VaultCrypto, VaultCryptoError, createVaultCrypto };
