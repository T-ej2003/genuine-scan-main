import { NotificationAudience, UserRole } from "@prisma/client";

const manufacturerOperationalNotificationTypes = new Set([
  "manufacturer_batch_assigned",
  "manufacturer_print_job_created",
  "manufacturer_print_job_confirmed",
  "system_print_job_created",
  "system_print_job_completed",
  "system_print_job_failed",
  "system_printer_status_changed",
]);

const normalizeType = (type?: string | null) => String(type || "").trim().toLowerCase();

export const isManufacturerOperationalNotificationType = (type?: string | null) =>
  manufacturerOperationalNotificationTypes.has(normalizeType(type));

export const canAudienceReceiveNotificationType = (audience: NotificationAudience, type?: string | null) => {
  if (audience === NotificationAudience.LICENSEE_ADMIN) {
    return !isManufacturerOperationalNotificationType(type);
  }

  return true;
};

export const hiddenNotificationTypesForRole = (role: UserRole) => {
  if (role === UserRole.LICENSEE_ADMIN || role === UserRole.ORG_ADMIN) {
    return Array.from(manufacturerOperationalNotificationTypes);
  }

  return [] as string[];
};

export const canRoleViewNotificationType = (role: UserRole, type?: string | null) => {
  return !hiddenNotificationTypesForRole(role).includes(normalizeType(type));
};
