"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.shouldRehashPassword = exports.verifyPassword = exports.hashPassword = void 0;
const argon2_1 = __importDefault(require("argon2"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const isArgonHash = (hash) => hash.startsWith("$argon2");
const hashPassword = async (password) => {
    // Argon2id recommended parameters: tuneable; keep sane defaults.
    return argon2_1.default.hash(password, {
        type: argon2_1.default.argon2id,
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
    });
};
exports.hashPassword = hashPassword;
const verifyPassword = async (storedHash, password) => {
    if (!storedHash)
        return false;
    if (isArgonHash(storedHash)) {
        try {
            return await argon2_1.default.verify(storedHash, password);
        }
        catch {
            return false;
        }
    }
    // Legacy bcrypt hashes.
    try {
        return await bcryptjs_1.default.compare(password, storedHash);
    }
    catch {
        return false;
    }
};
exports.verifyPassword = verifyPassword;
const shouldRehashPassword = (storedHash) => {
    if (!storedHash)
        return true;
    return !isArgonHash(storedHash);
};
exports.shouldRehashPassword = shouldRehashPassword;
//# sourceMappingURL=passwordService.js.map