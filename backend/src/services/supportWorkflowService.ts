import {
  IncidentActorType,
  IncidentEventType,
  IncidentHandoffStage,
  IncidentPriority,
  IncidentSeverity,
  IncidentStatus,
  SupportTicketStatus,
} from "@prisma/client";

import prisma from "../config/database";

const severitySlaHours: Record<IncidentSeverity, number> = {
  CRITICAL: 4,
  HIGH: 24,
  MEDIUM: 72,
  LOW: 168,
};

const computeSlaDueAt = (severity: IncidentSeverity) => {
  const hours = severitySlaHours[severity] || 72;
  return new Date(Date.now() + hours * 60 * 60_000);
};

const recordWorkflowEvent = async (input: {
  incidentId: string;
  actorType: IncidentActorType;
  actorUserId?: string | null;
  eventType: IncidentEventType;
  eventPayload?: any;
}) => {
  return prisma.incidentEvent.create({
    data: {
      incidentId: input.incidentId,
      actorType: input.actorType,
      actorUserId: input.actorUserId || null,
      eventType: input.eventType,
      eventPayload: input.eventPayload ?? null,
    },
  });
};

const stageRank: Record<IncidentHandoffStage, number> = {
  INTAKE: 1,
  REVIEW: 2,
  CONTAINMENT: 3,
  DOCUMENTATION: 4,
  RESOLUTION: 5,
  COMPLETE: 6,
};

const toHandoffStage = (status: IncidentStatus): IncidentHandoffStage => {
  if (status === IncidentStatus.CLOSED) return IncidentHandoffStage.COMPLETE;
  if (status === IncidentStatus.RESOLVED || status === IncidentStatus.MITIGATED) return IncidentHandoffStage.RESOLUTION;
  if (status === IncidentStatus.AWAITING_CUSTOMER || status === IncidentStatus.AWAITING_LICENSEE) {
    return IncidentHandoffStage.DOCUMENTATION;
  }
  if (
    status === IncidentStatus.CONTAINMENT ||
    status === IncidentStatus.ERADICATION ||
    status === IncidentStatus.RECOVERY
  ) {
    return IncidentHandoffStage.CONTAINMENT;
  }
  if (status === IncidentStatus.TRIAGED || status === IncidentStatus.TRIAGE || status === IncidentStatus.INVESTIGATING) {
    return IncidentHandoffStage.REVIEW;
  }
  return IncidentHandoffStage.INTAKE;
};

const toSupportTicketStatus = (status: IncidentStatus): SupportTicketStatus => {
  if (status === IncidentStatus.CLOSED || status === IncidentStatus.REJECTED_SPAM) return SupportTicketStatus.CLOSED;
  if (status === IncidentStatus.RESOLVED || status === IncidentStatus.MITIGATED) return SupportTicketStatus.RESOLVED;
  if (status === IncidentStatus.AWAITING_CUSTOMER || status === IncidentStatus.AWAITING_LICENSEE) {
    return SupportTicketStatus.WAITING_CUSTOMER;
  }
  if (
    status === IncidentStatus.TRIAGED ||
    status === IncidentStatus.TRIAGE ||
    status === IncidentStatus.INVESTIGATING ||
    status === IncidentStatus.CONTAINMENT ||
    status === IncidentStatus.ERADICATION ||
    status === IncidentStatus.RECOVERY
  ) {
    return SupportTicketStatus.IN_PROGRESS;
  }
  return SupportTicketStatus.OPEN;
};

const stageTimestampPatch = (
  current: {
    reviewAt: Date | null;
    containmentAt: Date | null;
    documentationAt: Date | null;
    resolutionAt: Date | null;
    completedAt: Date | null;
  },
  nextStage: IncidentHandoffStage,
  now: Date
) => {
  const patch: any = {};

  const ensure = (stage: IncidentHandoffStage, field: keyof typeof current) => {
    if (stageRank[nextStage] >= stageRank[stage] && !current[field]) {
      patch[field] = now;
    }
  };

  ensure(IncidentHandoffStage.REVIEW, "reviewAt");
  ensure(IncidentHandoffStage.CONTAINMENT, "containmentAt");
  ensure(IncidentHandoffStage.DOCUMENTATION, "documentationAt");
  ensure(IncidentHandoffStage.RESOLUTION, "resolutionAt");
  ensure(IncidentHandoffStage.COMPLETE, "completedAt");

  return patch;
};

const buildReferenceCode = (incidentId: string) => `SUP-${incidentId.replace(/-/g, "").slice(0, 10).toUpperCase()}`;

export const ensureIncidentWorkflowArtifacts = async (params: {
  incidentId: string;
  actorUserId?: string | null;
  actorType?: IncidentActorType;
  emitEvents?: boolean;
}) => {
  const incident = await prisma.incident.findUnique({
    where: { id: params.incidentId },
    select: {
      id: true,
      qrCodeValue: true,
      description: true,
      status: true,
      severity: true,
      priority: true,
      licenseeId: true,
      customerEmail: true,
      slaDueAt: true,
      createdAt: true,
      handoff: {
        select: {
          id: true,
          currentStage: true,
          intakeAt: true,
          reviewAt: true,
          containmentAt: true,
          documentationAt: true,
          resolutionAt: true,
          completedAt: true,
          slaDueAt: true,
        },
      },
      supportTicket: {
        select: {
          id: true,
          referenceCode: true,
          status: true,
          firstResponseAt: true,
          resolvedAt: true,
        },
      },
    },
  });

  if (!incident) return null;

  const now = new Date();
  const handoffStage = toHandoffStage(incident.status);
  const ticketStatus = toSupportTicketStatus(incident.status);

  const slaDueAt = incident.slaDueAt || computeSlaDueAt((incident.severity || IncidentSeverity.MEDIUM) as IncidentSeverity);

  let handoff = incident.handoff;
  if (!handoff) {
    handoff = await prisma.incidentHandoff.create({
      data: {
        incidentId: incident.id,
        currentStage: handoffStage,
        intakeAt: incident.createdAt,
        reviewAt: stageRank[handoffStage] >= stageRank[IncidentHandoffStage.REVIEW] ? now : null,
        containmentAt: stageRank[handoffStage] >= stageRank[IncidentHandoffStage.CONTAINMENT] ? now : null,
        documentationAt: stageRank[handoffStage] >= stageRank[IncidentHandoffStage.DOCUMENTATION] ? now : null,
        resolutionAt: stageRank[handoffStage] >= stageRank[IncidentHandoffStage.RESOLUTION] ? now : null,
        completedAt: stageRank[handoffStage] >= stageRank[IncidentHandoffStage.COMPLETE] ? now : null,
        slaDueAt,
      },
    });
  } else {
    const patch: any = {
      currentStage: handoffStage,
      slaDueAt,
      ...stageTimestampPatch(handoff, handoffStage, now),
    };

    handoff = await prisma.incidentHandoff.update({
      where: { incidentId: incident.id },
      data: patch,
    });
  }

  let ticket = incident.supportTicket;
  const referenceCode = ticket?.referenceCode || buildReferenceCode(incident.id);
  const shouldSetFirstResponse =
    ticketStatus !== SupportTicketStatus.OPEN &&
    ticketStatus !== SupportTicketStatus.WAITING_CUSTOMER &&
    !ticket?.firstResponseAt;
  const shouldSetResolvedAt =
    (ticketStatus === SupportTicketStatus.RESOLVED || ticketStatus === SupportTicketStatus.CLOSED) && !ticket?.resolvedAt;

  if (!ticket) {
    ticket = await prisma.supportTicket.create({
      data: {
        incidentId: incident.id,
        referenceCode,
        licenseeId: incident.licenseeId || null,
        customerEmail: incident.customerEmail || null,
        subject: `Support request for QR ${incident.qrCodeValue}`,
        status: ticketStatus,
        priority: (incident.priority || IncidentPriority.P3) as IncidentPriority,
        slaDueAt,
        firstResponseAt: shouldSetFirstResponse ? now : null,
        resolvedAt: shouldSetResolvedAt ? now : null,
      },
    });

    await prisma.supportTicketMessage.create({
      data: {
        ticketId: ticket.id,
        actorType: IncidentActorType.SYSTEM,
        actorUserId: params.actorUserId || null,
        message: `Ticket created from incident ${incident.id}. Intake started.`,
        isInternal: true,
      },
    });
  } else {
    ticket = await prisma.supportTicket.update({
      where: { incidentId: incident.id },
      data: {
        licenseeId: incident.licenseeId || null,
        customerEmail: incident.customerEmail || null,
        status: ticketStatus,
        priority: (incident.priority || IncidentPriority.P3) as IncidentPriority,
        slaDueAt,
        firstResponseAt: shouldSetFirstResponse ? now : ticket.firstResponseAt,
        resolvedAt:
          ticketStatus === SupportTicketStatus.RESOLVED || ticketStatus === SupportTicketStatus.CLOSED
            ? ticket.resolvedAt || now
            : null,
      },
    });
  }

  if (params.emitEvents) {
    await recordWorkflowEvent({
      incidentId: incident.id,
      actorType: params.actorType || IncidentActorType.SYSTEM,
      actorUserId: params.actorUserId || null,
      eventType: IncidentEventType.UPDATED_FIELDS,
      eventPayload: {
        workflow: {
          handoffStage,
          ticketStatus,
          ticketReference: referenceCode,
          slaDueAt: slaDueAt.toISOString(),
        },
      },
    });
  }

  return {
    handoff,
    ticket,
  };
};

export const addSupportTicketMessage = async (params: {
  ticketId: string;
  actorType: IncidentActorType;
  actorUserId?: string | null;
  message: string;
  isInternal?: boolean;
}) => {
  const content = String(params.message || "").trim();
  if (!content) return null;

  return prisma.supportTicketMessage.create({
    data: {
      ticketId: params.ticketId,
      actorType: params.actorType,
      actorUserId: params.actorUserId || null,
      message: content.slice(0, 4000),
      isInternal: Boolean(params.isInternal),
    },
  });
};

export const ticketSlaSnapshot = (slaDueAt?: Date | string | null) => {
  if (!slaDueAt) return { hasSla: false };
  const due = slaDueAt instanceof Date ? slaDueAt : new Date(slaDueAt);
  if (!Number.isFinite(due.getTime())) return { hasSla: false };

  const remainingMs = due.getTime() - Date.now();
  return {
    hasSla: true,
    dueAt: due.toISOString(),
    remainingMs,
    remainingMinutes: Math.round(remainingMs / 60_000),
    isBreached: remainingMs < 0,
  };
};
