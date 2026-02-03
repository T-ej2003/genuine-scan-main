"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createUser = createUser;
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const database_1 = __importDefault(require("../config/database"));
async function createUser(params) {
    const passwordHash = await bcryptjs_1.default.hash(params.password, 12);
    return database_1.default.user.create({
        data: {
            email: params.email.toLowerCase(),
            passwordHash,
            name: params.name,
            role: params.role,
            licenseeId: params.licenseeId ?? null,
            isActive: true,
            deletedAt: null,
        },
    });
}
//# sourceMappingURL=userService.js.map