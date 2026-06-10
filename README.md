# @rello-platform/vault-crypto

Canonical SpokeApiKeyVault encryption for the Rello platform, per the
**Q7 lock** (`CROSS-REPO-WALK-DECISIONS-260609.md §Q7 ¶3`): ONE shared
vault-encryption implementation replacing the 7 divergent spoke copies
(ground truth: 3 KDFs — SHA-256 ×4, PBKDF2-100k in Harvest Home, scrypt in
Newsletter Studio / MarketIntel — 2+ encoding formats, and The Drumbeat
uniquely placing the GCM authTag last).

## Canonical format (v2)

- **KDF:** scrypt (node defaults N=16384/r=8/p=1), fixed salt
  `rello-platform.vault-crypto.v2`, 32-byte key — memoized per instance.
- **Cipher:** AES-256-GCM, 12-byte IV, 16-byte authTag.
- **Encoding:** `v2:<iv>:<ciphertext>:<authTag>` — each segment base64,
  **authTag LAST consistently**.
- **Secret:** config-injected VALUE. The spoke reads
  `BILLING_VAULT_KEY_DERIVATION_SECRET` from its own env **lazily at call
  time** and passes the value in — this library never reads `process.env`
  (config-injection, mirroring `@rello-platform/signals`).
- **Versioning:** `keyId` maps to the spokes' existing `kmsKeyId` column;
  default `"v2-vault-secret"`.

## Usage

```ts
import { createVaultCrypto } from "@rello-platform/vault-crypto";

// In the spoke's vault wrapper — env read stays in the spoke, lazy:
function getVault() {
  const secret = process.env.BILLING_VAULT_KEY_DERIVATION_SECRET;
  if (!secret) throw new Error("BILLING_VAULT_KEY_DERIVATION_SECRET missing");
  return createVaultCrypto({ secret });
}

const vault = getVault();
const encryptedValue = vault.encrypt(plaintextApiKey);
// persist { encryptedValue, kmsKeyId: vault.keyId }

const plaintext = vault.decrypt(encryptedValue);
// THROWS VaultCryptoError (code FORMAT | AUTH) on malformed/tampered input —
// never returns null.
```

## Migration: one-shot re-encrypt of existing rows

`LEGACY_DECODERS` exports a byte-faithful decoder per spoke (keyed by
canonical `@rello-platform/slugs` app slug), each reproducing that spoke's
origin/main decrypt exactly:

| slug | KDF | legacy encoding |
| --- | --- | --- |
| `pathfinder-pro` | SHA-256 | hex `iv:authTag:ciphertext` |
| `harvest-home` | PBKDF2-100k, salt `rello-spoke-vault-v1` | base64 `iv‖authTag‖ciphertext` |
| `home-ready` | SHA-256 | base64 `iv‖authTag‖ciphertext` |
| `the-drumbeat` | SHA-256 | base64 `iv‖ciphertext‖authTag` (authTag LAST) |
| `open-house-hub` | SHA-256 | base64 `iv‖authTag‖ciphertext` |
| `newsletter-studio` | scrypt, salt `rello-platform-spoke-vault-v1` | base64 `iv‖authTag‖ciphertext` |
| `market-intel` | scrypt, salt `rello-platform.spoke-api-key-vault.v1` | `v1-app-secret:ivHex:tagHex:ctHex` |

```ts
import { createVaultCrypto, LEGACY_DECODERS } from "@rello-platform/vault-crypto";

const plaintext = LEGACY_DECODERS["harvest-home"](row.encryptedValue, legacySecret);
const vault = createVaultCrypto({ secret: newSecret });
await db.spokeApiKeyVault.update({
  where: { id: row.id },
  data: { encryptedValue: vault.encrypt(plaintext), kmsKeyId: vault.keyId },
});
```

Per the Q7 lock the rename is HARD-CUT (no dual-read): the new Railway var
is added to all 7 services with the SAME value before any code lands, then
one PR per spoke flips the read, then the old var is deleted.

## Install (git tag pin)

```bash
npm i 'github:rello-platform/vault-crypto#v0.1.0' --save
```

`dist/` is committed so git-based installs work without a build step.

## Develop

```bash
npm ci
npm run typecheck && npm run lint && npm test   # test builds dist then runs node --test
```

Node `>=22 <23` (engine-strict).
