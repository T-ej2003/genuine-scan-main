import fs from "fs/promises";
import path from "path";

import {
  GetObjectCommand,
  HeadBucketCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";

type ObjectStorageMode = "disabled" | "invalid" | "static-credentials" | "default-credentials";

type ObjectStorageConfiguration = {
  configured: boolean;
  mode: ObjectStorageMode;
  bucket: string | null;
  region: string | null;
  endpoint: string | null;
  reason?: string;
};

const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const configuredBucket = () =>
  String(process.env.OBJECT_STORAGE_BUCKET || "").trim();

const configuredEndpoint = () =>
  String(process.env.OBJECT_STORAGE_ENDPOINT || "").trim();

const configuredRegion = () =>
  String(process.env.OBJECT_STORAGE_REGION || process.env.AWS_REGION || "").trim();

const configuredAccessKey = () =>
  String(process.env.OBJECT_STORAGE_ACCESS_KEY || "").trim();

const configuredSecretKey = () =>
  String(process.env.OBJECT_STORAGE_SECRET_KEY || "").trim();

const forcePathStyle = () =>
  parseBool(process.env.OBJECT_STORAGE_FORCE_PATH_STYLE, Boolean(configuredEndpoint()));

const resolveObjectStorageConfiguration = (): ObjectStorageConfiguration => {
  const bucket = configuredBucket() || null;
  const endpoint = configuredEndpoint() || null;
  const region = configuredRegion() || null;
  const accessKey = configuredAccessKey();
  const secretKey = configuredSecretKey();
  const hasAccessKey = Boolean(accessKey);
  const hasSecretKey = Boolean(secretKey);
  const hasStaticCredentials = hasAccessKey || hasSecretKey;
  const hasCompleteStaticCredentials = hasAccessKey && hasSecretKey;

  if (!bucket && !region && !endpoint && !hasStaticCredentials) {
    return {
      configured: false,
      mode: "disabled",
      bucket,
      region,
      endpoint,
      reason: "OBJECT_STORAGE_BUCKET and OBJECT_STORAGE_REGION/AWS_REGION are not set.",
    };
  }

  if (!bucket) {
    return {
      configured: false,
      mode: "invalid",
      bucket,
      region,
      endpoint,
      reason: "OBJECT_STORAGE_BUCKET is required when object storage is enabled.",
    };
  }

  if (!region) {
    return {
      configured: false,
      mode: "invalid",
      bucket,
      region,
      endpoint,
      reason: "OBJECT_STORAGE_REGION or AWS_REGION is required when object storage is enabled.",
    };
  }

  if (hasStaticCredentials && !hasCompleteStaticCredentials) {
    return {
      configured: false,
      mode: "invalid",
      bucket,
      region,
      endpoint,
      reason: "OBJECT_STORAGE_ACCESS_KEY and OBJECT_STORAGE_SECRET_KEY must be set together.",
    };
  }

  if (endpoint && !hasCompleteStaticCredentials) {
    return {
      configured: false,
      mode: "invalid",
      bucket,
      region,
      endpoint,
      reason:
        "OBJECT_STORAGE_ENDPOINT requires OBJECT_STORAGE_ACCESS_KEY and OBJECT_STORAGE_SECRET_KEY for custom S3-compatible storage.",
    };
  }

  if (hasCompleteStaticCredentials) {
    return {
      configured: true,
      mode: "static-credentials",
      bucket,
      region,
      endpoint,
    };
  }

  return {
    configured: true,
    mode: "default-credentials",
    bucket,
    region,
    endpoint,
  };
};

let client: S3Client | null = null;

const getClient = () => {
  const configuration = resolveObjectStorageConfiguration();
  if (!configuration.configured) return null;
  if (!client) {
    const accessKey = configuredAccessKey();
    const secretKey = configuredSecretKey();
    const endpoint = configuredEndpoint();

    client = new S3Client({
      region: configuredRegion(),
      ...(endpoint ? { endpoint } : {}),
      forcePathStyle: forcePathStyle(),
      ...(accessKey && secretKey
        ? {
            credentials: {
              accessKeyId: accessKey,
              secretAccessKey: secretKey,
            },
          }
        : {}),
    });
  }
  return client;
};

export const getObjectStorageConfiguration = () => resolveObjectStorageConfiguration();

export const isObjectStorageConfigured = () => resolveObjectStorageConfiguration().configured;

export const uploadObjectFromFile = async (params: {
  objectKey: string;
  filePath: string;
  contentType?: string | null;
}) => {
  const s3 = getClient();
  if (!s3) return { uploaded: false as const, key: params.objectKey };

  const buffer = await fs.readFile(params.filePath);
  await s3.send(
    new PutObjectCommand({
      Bucket: configuredBucket(),
      Key: params.objectKey,
      Body: buffer,
      ContentType: params.contentType || "application/octet-stream",
    })
  );

  return { uploaded: true as const, key: params.objectKey };
};

export const downloadObjectBuffer = async (objectKey: string) => {
  const s3 = getClient();
  if (!s3) return null;

  const response = await s3.send(
    new GetObjectCommand({
      Bucket: configuredBucket(),
      Key: objectKey,
    })
  );

  if (!response.Body) return null;
  const bytes = await response.Body.transformToByteArray();
  return Buffer.from(bytes);
};

export const removeLocalFileIfExists = async (filePath: string) => {
  try {
    await fs.unlink(filePath);
  } catch (error: any) {
    if (error?.code !== "ENOENT") {
      console.error(`[object-storage] failed to delete local file ${filePath}`, error);
    }
  }
};

export const getObjectStorageHealth = async () => {
  const configuration = resolveObjectStorageConfiguration();
  const s3 = getClient();
  if (!s3) {
    return {
      configured: false,
      ready: false,
      bucket: configuration.bucket,
      region: configuration.region,
      endpoint: configuration.endpoint,
      mode: configuration.mode,
      reason: configuration.reason,
    };
  }

  try {
    await s3.send(new HeadBucketCommand({ Bucket: configuredBucket() }));
    return {
      configured: true,
      ready: true,
      bucket: configuration.bucket,
      region: configuration.region,
      endpoint: configuration.endpoint,
      mode: configuration.mode,
    };
  } catch (error: any) {
    return {
      configured: true,
      ready: false,
      bucket: configuration.bucket,
      region: configuration.region,
      endpoint: configuration.endpoint,
      mode: configuration.mode,
      reason: error?.message || "Object storage unreachable",
    };
  }
};

export const resolveObjectStorageKey = (fileName: string) => path.basename(String(fileName || "").trim());
