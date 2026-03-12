import { Request, Response } from "express";
import { z } from "zod";
import {
  getConnectorReleaseManifest,
  getLatestConnectorRelease,
  resolveConnectorDownload,
  type ConnectorPlatformKey,
} from "../services/connectorReleaseService";

const downloadParamsSchema = z.object({
  version: z.string().trim().min(3),
  platform: z.enum(["macos", "windows"]),
});

const normalizeBaseUrl = (value?: string | null) => String(value || "").trim().replace(/\/+$/, "");

const resolveConnectorBaseUrl = (req: Request) => {
  const explicitApi = normalizeBaseUrl(process.env.PUBLIC_API_BASE_URL);
  if (explicitApi) return explicitApi;

  const explicitWeb = normalizeBaseUrl(process.env.WEB_APP_BASE_URL);
  if (explicitWeb) return explicitWeb;

  const origin = req.get("origin");
  if (origin) return normalizeBaseUrl(origin);

  return `${req.protocol}://${req.get("host") || "localhost"}`;
};

export const listConnectorReleasesController = async (req: Request, res: Response) => {
  try {
    const baseUrl = resolveConnectorBaseUrl(req);
    const manifest = getConnectorReleaseManifest(baseUrl);
    return res.json({ success: true, data: manifest });
  } catch (error: any) {
    console.error("listConnectorReleasesController error:", error);
    return res.status(503).json({
      success: false,
      error: "Connector downloads are not available right now.",
    });
  }
};

export const getLatestConnectorReleaseController = async (req: Request, res: Response) => {
  try {
    const baseUrl = resolveConnectorBaseUrl(req);
    const release = getLatestConnectorRelease(baseUrl);
    return res.json({ success: true, data: release });
  } catch (error: any) {
    console.error("getLatestConnectorReleaseController error:", error);
    return res.status(503).json({
      success: false,
      error: "Connector downloads are not available right now.",
    });
  }
};

export const downloadConnectorReleaseController = async (req: Request, res: Response) => {
  const parsed = downloadParamsSchema.safeParse(req.params || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: "Invalid connector download request." });
  }

  try {
    const artifact = resolveConnectorDownload(parsed.data.version, parsed.data.platform as ConnectorPlatformKey);
    res.setHeader("Content-Type", artifact.contentType || "application/octet-stream");
    res.setHeader("Content-Length", String(artifact.bytes));
    res.setHeader("Content-Disposition", `attachment; filename="${artifact.filename}"`);
    res.setHeader("Cache-Control", "public, max-age=300");
    res.setHeader("X-Checksum-Sha256", artifact.sha256);
    return res.sendFile(artifact.filePath);
  } catch (error: any) {
    console.error("downloadConnectorReleaseController error:", error);
    return res.status(404).json({
      success: false,
      error: "That connector package is not available.",
    });
  }
};
