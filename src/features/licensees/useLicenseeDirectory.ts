import { useEffect, useMemo, useState } from "react";
import { saveAs } from "file-saver";

import apiClient from "@/lib/api-client";
import { onMutationEvent } from "@/lib/mutation-events";
import type { LicenseeRow } from "@/features/licensees/types";

type ToastLike = (options: {
  title?: string;
  description?: string;
  variant?: "default" | "destructive";
}) => unknown;

export function useLicenseeDirectory(toast: ToastLike) {
  const [loading, setLoading] = useState(true);
  const [licensees, setLicensees] = useState<LicenseeRow[]>([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "inactive">("all");

  const load = async () => {
    setLoading(true);
    const response = await apiClient.getLicensees();
    if (!response.success) {
      toast({
        title: "Failed to load",
        description: response.error || "Could not load licensees",
        variant: "destructive",
      });
      setLicensees([]);
      setLoading(false);
      return;
    }
    setLicensees(((response.data as any) || []) as LicenseeRow[]);
    setLoading(false);
  };

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const off = onMutationEvent(() => {
      void load();
    });
    return off;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();

    return (licensees || [])
      .filter((licensee) => {
        if (statusFilter === "active") return !!licensee.isActive;
        if (statusFilter === "inactive") return !licensee.isActive;
        return true;
      })
      .filter((licensee) => {
        if (!query) return true;
        return (
          (licensee.name || "").toLowerCase().includes(query) ||
          (licensee.prefix || "").toLowerCase().includes(query) ||
          (licensee.description || "").toLowerCase().includes(query)
        );
      });
  }, [licensees, search, statusFilter]);

  const exportCsv = async () => {
    try {
      const blob = await apiClient.exportLicenseesCsv();
      saveAs(blob, "licensees.csv");
    } catch (error: any) {
      toast({
        title: "Export failed",
        description: error?.message || "Could not export",
        variant: "destructive",
      });
    }
  };

  return {
    loading,
    licensees,
    setLicensees,
    search,
    setSearch,
    statusFilter,
    setStatusFilter,
    filtered,
    load,
    exportCsv,
  };
}
