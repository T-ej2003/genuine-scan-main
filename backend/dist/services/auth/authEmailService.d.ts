export declare const sendAuthEmail: (input: {
    toAddress: string;
    subject: string;
    text: string;
    html?: string;
    template: string;
    orgId?: string | null;
    licenseeId?: string | null;
    actorUserId?: string | null;
    ipHash?: string | null;
    userAgent?: string | null;
}) => Promise<{
    delivered: boolean;
    error?: string | null;
    attemptedFrom?: string | null;
    usedFrom?: string | null;
    replyTo?: string | null;
    providerMessageId?: string | null;
    providerResponse?: string | null;
    acceptedRecipients?: string[];
    rejectedRecipients?: string[];
}>;
//# sourceMappingURL=authEmailService.d.ts.map