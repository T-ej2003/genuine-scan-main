"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createUser = createUser;
const database_1 = __importDefault(require("../config/database"));
const passwordService_1 = require("./auth/passwordService");
async function createUser(params) {
    const passwordHash = await (0, passwordService_1.hashPassword)(params.password);
    const licenseeId = params.licenseeId ?? null;
    const orgId = licenseeId
        ? (await database_1.default.licensee.findUnique({
            where: { id: licenseeId },
            select: { orgId: true },
        }))?.orgId ?? null
        : null;
    return database_1.default.user.create({
        data: {
            email: params.email.toLowerCase(),
            passwordHash,
            name: params.name,
            role: params.role,
            licenseeId,
            orgId,
            isActive: true,
            deletedAt: null,
        },
    });
}
//# sourceMappingURL=userService.js.map