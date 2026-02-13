import { UserRole } from "@prisma/client";
type IncidentEmailActorUser = {
    id?: string | null;
    role?: UserRole | string | null;
    email?: string | null;
    name?: string | null;
};
type SendIncidentEmailInput = {
    incidentId: string;
    licenseeId?: string | null;
    toAddress: string;
    subject: string;
    text: string;
    html?: string;
    actorUser?: IncidentEmailActorUser | null;
    senderMode?: "actor" | "system";
    template?: string;
};
type SendIncidentEmailResult = {
    delivered: boolean;
    providerMessageId?: string | null;
    error?: string | null;
    attemptedFrom?: string | null;
    usedFrom?: string | null;
    replyTo?: string | null;
};
export declare const sendIncidentEmail: (input: SendIncidentEmailInput) => Promise<SendIncidentEmailResult>;
export declare const getSuperadminAlertEmails: () => Promise<string[]>;
export declare const __resetIncidentEmailTransporterForTests: () => void;
export {};
//# sourceMappingURL=incidentEmailService.d.ts.map