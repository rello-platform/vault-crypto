import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createCipheriv,
  createHash,
  pbkdf2Sync,
  randomBytes,
  scryptSync,
} from "node:crypto";
import {
  createVaultCrypto,
  DEFAULT_KEY_ID,
  LEGACY_DECODERS,
  VaultCryptoError,
} from "../dist/index.js";

const SECRET = "test-vault-secret-0123456789abcdef-0123456789abcdef"; // >= 32 chars
const OTHER_SECRET = "other-vault-secret-fedcba9876543210-fedcba9876543210";
const PLAINTEXT = "ak_1778714154714_7b2951bf:super-secret-spoke-api-key-payload ✓ utf8 ✓";

// ---------------------------------------------------------------------------
// Legacy fixture generators — each reproduces its spoke's origin/main
// ENCRYPT path verbatim (same KDF, same packing order, same encoding), so
// the decoders are tested against byte-faithful legacy ciphertexts.
// ---------------------------------------------------------------------------

/** PathfinderPro origin/main: sha256 key; hex `iv:authTag:ciphertext`. */
function encryptLegacyPathfinderPro(plaintext, secret) {
  const key = createHash("sha256").update(secret).digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [iv, authTag, encrypted].map((b) => b.toString("hex")).join(":");
}

/** Harvest Home origin/main: pbkdf2-100k key; base64(iv||authTag||ciphertext). */
function encryptLegacyHarvestHome(plaintext, secret) {
  const key = pbkdf2Sync(secret, "rello-spoke-vault-v1", 100_000, 32, "sha256");
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]).toString("base64");
}

/** HomeReady origin/main: sha256 key (utf8 update); base64(iv||authTag||ciphertext). */
function encryptLegacyHomeReady(plaintext, secret) {
  const key = createHash("sha256").update(secret, "utf8").digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]).toString("base64");
}

/** The Drumbeat origin/main: sha256 key; base64(iv||ciphertext||authTag) — authTag LAST. */
function encryptLegacyTheDrumbeat(plaintext, secret) {
  const key = createHash("sha256").update(secret).digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, authTag]).toString("base64");
}

/** Open House Hub origin/main: sha256 key; base64(iv||authTag||ciphertext). */
function encryptLegacyOpenHouseHub(plaintext, secret) {
  const key = createHash("sha256").update(secret).digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString("base64");
}

/** Newsletter Studio origin/main: scrypt(secret, Buffer("rello-platform-spoke-vault-v1"), 32); base64(iv||authTag||ciphertext). */
function encryptLegacyNewsletterStudio(plaintext, secret) {
  const key = scryptSync(secret, Buffer.from("rello-platform-spoke-vault-v1"), 32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]).toString("base64");
}

/** MarketIntel origin/main: scrypt(secret, "rello-platform.spoke-api-key-vault.v1", 32); `v1-app-secret:ivHex:tagHex:ctHex`. */
function encryptLegacyMarketIntel(plaintext, secret) {
  const key = scryptSync(secret, "rello-platform.spoke-api-key-vault.v1", 32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1-app-secret:${iv.toString("hex")}:${tag.toString("hex")}:${ciphertext.toString("hex")}`;
}

const LEGACY_FIXTURE_GENERATORS = {
  "pathfinder-pro": encryptLegacyPathfinderPro,
  "harvest-home": encryptLegacyHarvestHome,
  "home-ready": encryptLegacyHomeReady,
  "the-drumbeat": encryptLegacyTheDrumbeat,
  "open-house-hub": encryptLegacyOpenHouseHub,
  "newsletter-studio": encryptLegacyNewsletterStudio,
  "market-intel": encryptLegacyMarketIntel,
};

// ---------------------------------------------------------------------------
// Canonical implementation
// ---------------------------------------------------------------------------

describe("createVaultCrypto — config validation", () => {
  it("throws CONFIG on missing/empty secret", () => {
    assert.throws(() => createVaultCrypto({ secret: "" }), (err) => {
      assert.ok(err instanceof VaultCryptoError);
      assert.equal(err.code, "CONFIG");
      return true;
    });
  });

  it("throws CONFIG on secret shorter than 32 chars", () => {
    assert.throws(() => createVaultCrypto({ secret: "too-short" }), (err) => {
      assert.equal(err.code, "CONFIG");
      assert.match(err.message, /32 chars/);
      return true;
    });
  });

  it("throws CONFIG on empty keyId override", () => {
    assert.throws(() => createVaultCrypto({ secret: SECRET, keyId: "" }), (err) => {
      assert.equal(err.code, "CONFIG");
      return true;
    });
  });

  it("defaults keyId to v2-vault-secret and honors overrides", () => {
    assert.equal(DEFAULT_KEY_ID, "v2-vault-secret");
    assert.equal(createVaultCrypto({ secret: SECRET }).keyId, "v2-vault-secret");
    assert.equal(createVaultCrypto({ secret: SECRET, keyId: "v3-kms" }).keyId, "v3-kms");
  });
});

describe("canonical v2 encrypt/decrypt", () => {
  const vault = createVaultCrypto({ secret: SECRET });

  it("round-trips utf8 plaintext", () => {
    const ct = vault.encrypt(PLAINTEXT);
    assert.equal(vault.decrypt(ct), PLAINTEXT);
  });

  it("emits version-prefixed 4-segment base64 with 12B iv and 16B authTag LAST", () => {
    const ct = vault.encrypt(PLAINTEXT);
    const parts = ct.split(":");
    assert.equal(parts.length, 4);
    assert.equal(parts[0], "v2");
    assert.equal(Buffer.from(parts[1], "base64").length, 12); // iv
    assert.ok(Buffer.from(parts[2], "base64").length > 0); // ciphertext
    assert.equal(Buffer.from(parts[3], "base64").length, 16); // authTag last
  });

  it("produces a fresh IV per call (no ciphertext reuse)", () => {
    assert.notEqual(vault.encrypt(PLAINTEXT), vault.encrypt(PLAINTEXT));
  });

  it("rejects empty plaintext", () => {
    assert.throws(() => vault.encrypt(""), (err) => {
      assert.equal(err.code, "FORMAT");
      return true;
    });
  });

  it("throws AUTH on tampered ciphertext (never null)", () => {
    const ct = vault.encrypt(PLAINTEXT);
    const parts = ct.split(":");
    const body = Buffer.from(parts[2], "base64");
    body[0] ^= 0xff;
    parts[2] = body.toString("base64");
    assert.throws(() => vault.decrypt(parts.join(":")), (err) => {
      assert.ok(err instanceof VaultCryptoError);
      assert.equal(err.code, "AUTH");
      assert.match(err.message, /authentication failed/i);
      return true;
    });
  });

  it("throws AUTH on tampered authTag", () => {
    const ct = vault.encrypt(PLAINTEXT);
    const parts = ct.split(":");
    const tag = Buffer.from(parts[3], "base64");
    tag[15] ^= 0x01;
    parts[3] = tag.toString("base64");
    assert.throws(() => vault.decrypt(parts.join(":")), (err) => {
      assert.equal(err.code, "AUTH");
      return true;
    });
  });

  it("throws AUTH under a different secret", () => {
    const ct = vault.encrypt(PLAINTEXT);
    const other = createVaultCrypto({ secret: OTHER_SECRET });
    assert.throws(() => other.decrypt(ct), (err) => {
      assert.equal(err.code, "AUTH");
      return true;
    });
  });

  it("throws FORMAT on wrong segment count, pointing at LEGACY_DECODERS", () => {
    assert.throws(() => vault.decrypt("deadbeef:cafebabe:0123"), (err) => {
      assert.equal(err.code, "FORMAT");
      assert.match(err.message, /LEGACY_DECODERS/);
      return true;
    });
  });

  it("throws FORMAT on unknown version prefix", () => {
    const ct = vault.encrypt(PLAINTEXT).replace(/^v2:/, "v9:");
    assert.throws(() => vault.decrypt(ct), (err) => {
      assert.equal(err.code, "FORMAT");
      assert.match(err.message, /v9/);
      return true;
    });
  });

  it("throws FORMAT on bad IV / authTag lengths and empty ciphertext", () => {
    const goodIv = Buffer.alloc(12).toString("base64");
    const goodTag = Buffer.alloc(16).toString("base64");
    const shortIv = Buffer.alloc(7).toString("base64");
    const shortTag = Buffer.alloc(9).toString("base64");
    for (const bad of [
      `v2:${shortIv}:${Buffer.from("x").toString("base64")}:${goodTag}`,
      `v2:${goodIv}:${Buffer.from("x").toString("base64")}:${shortTag}`,
      `v2:${goodIv}::${goodTag}`,
    ]) {
      assert.throws(() => vault.decrypt(bad), (err) => {
        assert.equal(err.code, "FORMAT");
        return true;
      });
    }
  });
});

// ---------------------------------------------------------------------------
// Legacy decoders
// ---------------------------------------------------------------------------

describe("LEGACY_DECODERS — registry shape", () => {
  it("exposes exactly the 7 legacy spokes by canonical slug", () => {
    assert.deepEqual(Object.keys(LEGACY_DECODERS).sort(), [
      "harvest-home",
      "home-ready",
      "market-intel",
      "newsletter-studio",
      "open-house-hub",
      "pathfinder-pro",
      "the-drumbeat",
    ]);
  });

  it("is frozen", () => {
    assert.ok(Object.isFrozen(LEGACY_DECODERS));
  });
});

describe("LEGACY_DECODERS — byte-faithful decode of legacy fixtures", () => {
  for (const [slug, generate] of Object.entries(LEGACY_FIXTURE_GENERATORS)) {
    it(`${slug}: decodes a fixture produced by its origin/main encrypt path`, () => {
      const fixture = generate(PLAINTEXT, SECRET);
      assert.equal(LEGACY_DECODERS[slug](fixture, SECRET), PLAINTEXT);
    });

    it(`${slug}: throws LEGACY_AUTH under the wrong legacy secret`, () => {
      const fixture = generate(PLAINTEXT, SECRET);
      assert.throws(() => LEGACY_DECODERS[slug](fixture, OTHER_SECRET), (err) => {
        assert.ok(err instanceof VaultCryptoError);
        assert.equal(err.code, "LEGACY_AUTH");
        assert.match(err.message, new RegExp(slug));
        return true;
      });
    });
  }

  it("cross-decoder isolation: a Drumbeat (authTag-last) blob does NOT decode under the authTag-second decoders", () => {
    const fixture = encryptLegacyTheDrumbeat(PLAINTEXT, SECRET);
    assert.throws(() => LEGACY_DECODERS["home-ready"](fixture, SECRET), (err) => {
      assert.equal(err.code, "LEGACY_AUTH");
      return true;
    });
  });

  it("pathfinder-pro: LEGACY_FORMAT on wrong segment count", () => {
    assert.throws(() => LEGACY_DECODERS["pathfinder-pro"]("aa:bb", SECRET), (err) => {
      assert.equal(err.code, "LEGACY_FORMAT");
      return true;
    });
  });

  it("harvest-home: LEGACY_FORMAT on too-short envelope", () => {
    assert.throws(
      () => LEGACY_DECODERS["harvest-home"](Buffer.alloc(10).toString("base64"), SECRET),
      (err) => {
        assert.equal(err.code, "LEGACY_FORMAT");
        return true;
      },
    );
  });

  it("market-intel: LEGACY_FORMAT on unknown embedded kmsKeyId", () => {
    const fixture = encryptLegacyMarketIntel(PLAINTEXT, SECRET).replace(/^v1-app-secret/, "v9-unknown");
    assert.throws(() => LEGACY_DECODERS["market-intel"](fixture, SECRET), (err) => {
      assert.equal(err.code, "LEGACY_FORMAT");
      assert.match(err.message, /v9-unknown/);
      return true;
    });
  });

  it("the-drumbeat: LEGACY_FORMAT on too-short envelope", () => {
    assert.throws(
      () => LEGACY_DECODERS["the-drumbeat"](Buffer.alloc(20).toString("base64"), SECRET),
      (err) => {
        assert.equal(err.code, "LEGACY_FORMAT");
        return true;
      },
    );
  });
});

describe("migration one-shot: legacy decode → canonical re-encrypt", () => {
  it("re-encrypts every spoke's legacy row to v2 and round-trips", () => {
    const vault = createVaultCrypto({ secret: SECRET });
    for (const [slug, generate] of Object.entries(LEGACY_FIXTURE_GENERATORS)) {
      const legacyRow = generate(PLAINTEXT, SECRET);
      const plaintext = LEGACY_DECODERS[slug](legacyRow, SECRET);
      const v2Row = vault.encrypt(plaintext);
      assert.ok(v2Row.startsWith("v2:"), `${slug}: re-encrypted row must be v2-prefixed`);
      assert.equal(vault.decrypt(v2Row), PLAINTEXT, `${slug}: migration round-trip`);
      assert.equal(vault.keyId, "v2-vault-secret");
    }
  });
});
