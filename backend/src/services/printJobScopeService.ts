import { Prisma, UserRole } from "@prisma/client";

export type PrintJobScope = {
  role: UserRole;
  userId: string;
  licenseeId?: string | null;
};

export const buildScopedPrintJobWhere = (
  scope: PrintJobScope,
  extraWhere: Prisma.PrintJobWhereInput = {}
): Prisma.PrintJobWhereInput => {
  if (scope.role === UserRole.SUPER_ADMIN || scope.role === UserRole.PLATFORM_SUPER_ADMIN) {
    return {
      ...extraWhere,
      ...(scope.licenseeId ? { batch: { is: { licenseeId: scope.licenseeId } } } : {}),
    };
  }

  if (scope.role === UserRole.LICENSEE_ADMIN || scope.role === UserRole.ORG_ADMIN) {
    return {
      ...extraWhere,
      batch: { is: { licenseeId: scope.licenseeId || "__denied__" } },
    };
  }

  return {
    ...extraWhere,
    manufacturerId: scope.userId,
  };
};
