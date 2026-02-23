export declare const hashPassword: (password: string) => Promise<string>;
export declare const verifyPassword: (storedHash: string, password: string) => Promise<boolean>;
export declare const shouldRehashPassword: (storedHash: string) => boolean;
//# sourceMappingURL=passwordService.d.ts.map