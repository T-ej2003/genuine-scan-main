import argon2 from "argon2";
import bcrypt from "bcryptjs";

const isArgonHash = (hash: string) => hash.startsWith("$argon2");

export const hashPassword = async (password: string) => {
  // Argon2id recommended parameters: tuneable; keep sane defaults.
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });
};

export const verifyPassword = async (storedHash: string, password: string) => {
  if (!storedHash) return false;
  if (isArgonHash(storedHash)) {
    try {
      return await argon2.verify(storedHash, password);
    } catch {
      return false;
    }
  }
  // Legacy bcrypt hashes.
  try {
    return await bcrypt.compare(password, storedHash);
  } catch {
    return false;
  }
};

export const shouldRehashPassword = (storedHash: string) => {
  if (!storedHash) return true;
  return !isArgonHash(storedHash);
};

