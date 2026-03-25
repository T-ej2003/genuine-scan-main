const assert = require("assert");
const { NotificationAudience, UserRole } = require("@prisma/client");

const {
  canAudienceReceiveNotificationType,
  canRoleViewNotificationType,
  isManufacturerOperationalNotificationType,
} = require("../dist/services/notificationVisibility");

assert.strictEqual(
  isManufacturerOperationalNotificationType("system_print_job_completed"),
  true,
  "system print completion should be treated as manufacturer operational"
);

assert.strictEqual(
  canAudienceReceiveNotificationType(NotificationAudience.LICENSEE_ADMIN, "system_printer_status_changed"),
  false,
  "licensee broadcast rows should not be created for manufacturer printer-status events"
);

assert.strictEqual(
  canRoleViewNotificationType(UserRole.LICENSEE_ADMIN, "system_print_job_failed"),
  false,
  "licensee users should not see manufacturer operational system notifications"
);

assert.strictEqual(
  canRoleViewNotificationType(UserRole.MANUFACTURER_ADMIN, "system_print_job_failed"),
  true,
  "manufacturer users should keep manufacturer operational notifications"
);

assert.strictEqual(
  canRoleViewNotificationType(UserRole.SUPER_ADMIN, "qr_request_created"),
  true,
  "super admins should keep platform approval notifications"
);

console.log("notification visibility tests passed");
