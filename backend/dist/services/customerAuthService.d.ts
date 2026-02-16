export declare const requestEmailOtp: (input: {
    email: string;
    name?: string | null;
}) => Promise<{
    delivered: boolean;
    expiresAt: string;
}>;
export declare const verifyEmailOtp: (input: {
    email: string;
    otp: string;
    name?: string | null;
}) => Promise<{
    id: string;
    email: string;
    name: string | null;
    createdAt: Date;
    updatedAt: Date;
    provider: import(".prisma/client").$Enums.CustomerAuthProvider;
    providerId: string | null;
}>;
export declare const authenticateWithGoogle: (input: {
    idToken: string;
}) => Promise<{
    id: string;
    email: string;
    name: string | null;
    createdAt: Date;
    updatedAt: Date;
    provider: import(".prisma/client").$Enums.CustomerAuthProvider;
    providerId: string | null;
}>;
//# sourceMappingURL=customerAuthService.d.ts.map