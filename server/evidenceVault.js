import crypto from "node:crypto";

const FORMAT_VERSION = "v1";
const IV_BYTES = 12;

export function createEvidenceVault(encodedKey) {
  if (typeof encodedKey !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(encodedKey)) {
    throw new Error("DATA_ENCRYPTION_KEY must be a base64-encoded 32-byte key.");
  }
  const key = Buffer.from(encodedKey, "base64");
  if (key.length !== 32 || key.toString("base64").replace(/=+$/, "") !== encodedKey.replace(/=+$/, "")) {
    throw new Error("DATA_ENCRYPTION_KEY must be a base64-encoded 32-byte key.");
  }

  return Object.freeze({
    encrypt(plaintext) {
      if (typeof plaintext !== "string" || plaintext.length === 0) throw new TypeError("Evidence must be a non-empty string.");
      const iv = crypto.randomBytes(IV_BYTES);
      const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
      const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
      const tag = cipher.getAuthTag();
      return [FORMAT_VERSION, iv.toString("base64url"), tag.toString("base64url"), ciphertext.toString("base64url")].join(":");
    },
    decrypt(payload) {
      if (typeof payload !== "string") throw new TypeError("Encrypted evidence is invalid.");
      const [version, ivValue, tagValue, ciphertextValue, extra] = payload.split(":");
      if (version !== FORMAT_VERSION || !ivValue || !tagValue || !ciphertextValue || extra !== undefined) {
        throw new Error("Encrypted evidence is invalid.");
      }
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivValue, "base64url"));
      decipher.setAuthTag(Buffer.from(tagValue, "base64url"));
      return Buffer.concat([decipher.update(Buffer.from(ciphertextValue, "base64url")), decipher.final()]).toString("utf8");
    },
  });
}
