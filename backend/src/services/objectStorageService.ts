import fs from "fs/promises";
import path from "path";

import {
  GetObjectCommand,
  HeadBucketCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";

const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const configuredBucket = () =>
  String(process.env.OBJECT_STORAGE_BUCKET || process.env.S3_BUCKET || process.env.MINIO_BUCKET || "").trim();

const configuredEndpoint = () =>
  String(process.env.OBJECT_STORAGE_ENDPOINT || process.env.S3_ENDPOINT || process.env.MINIO_ENDPOINT || "").trim();

const configuredRegion = () =>
  String(process.env.OBJECT_STORAGE_REGION || process.env.S3_REGION || process.env.AWS_REGION || "us-east-1").trim();

const configuredAccessKey = () =>
  String(process.env.OBJECT_STORAGE_ACCESS_KEY || process.env.S3_ACCESS_KEY || process.env.MINIO_ROOT_USER || "").trim();

const configuredSecretKey = () =>
  String(process.env.OBJECT_STORAGE_SECRET_KEY || process.env.S3_SECRET_KEY || process.env.MINIO_ROOT_PASSWORD || "").trim();

const forcePathStyle = () =>
  parseBool(process.env.OBJECT_STORAGE_FORCE_PATH_STYLE, true);

const objectStorageConfigured = () =>
  Boolean(configuredBucket() && configuredEndpoint() && configuredAccessKey() && configuredSecretKey());

let client: S3Client | null = null;

const getClient = () => {
  if (!objectStorageConfigured()) return null;
  if (!client) {
    client = new S3Client({
      region: configuredRegion(),
      endpoint: configuredEndpoint(),
      forcePathStyle: forcePathStyle(),
      credentials: {
        accessKeyId: configuredAccessKey(),
        secretAccessKey: configuredSecretKey(),
      },
    });
  }
  return client;
};

export const isObjectStorageConfigured = () => objectStorageConfigured();

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
  const s3 = getClient();
  if (!s3) return { configured: false, ready: false, bucket: configuredBucket() || null };

  try {
    await s3.send(new HeadBucketCommand({ Bucket: configuredBucket() }));
    return { configured: true, ready: true, bucket: configuredBucket() };
  } catch {
    return { configured: true, ready: false, bucket: configuredBucket() };
  }
};

export const resolveObjectStorageKey = (fileName: string) => path.basename(String(fileName || "").trim());
