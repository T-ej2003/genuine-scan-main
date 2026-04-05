import { createAdminOpsApi } from "@/lib/api/internal-client-admin-ops";
import { createAuthApi } from "@/lib/api/internal-client-auth";
import { createApiClientCore, type ApiResponse } from "@/lib/api/internal-client-core";
import { createLicenseeQrApi } from "@/lib/api/internal-client-licensee-qr";
import { createPrintingApi } from "@/lib/api/internal-client-printing";
import { createVerifySupportApi } from "@/lib/api/internal-client-verify-support";

const core = createApiClientCore();

const apiClient = {
  setToken: core.setToken,
  getToken: core.getToken,
  logout: core.logout,
  ...createAuthApi(core),
  ...createLicenseeQrApi(core),
  ...createPrintingApi(core),
  ...createAdminOpsApi(core),
  ...createVerifySupportApi(core),
};

export default apiClient;
export { apiClient };
export type { ApiResponse };
