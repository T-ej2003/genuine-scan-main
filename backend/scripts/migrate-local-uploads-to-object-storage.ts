import fs from "fs/promises";
import path from "path";

import dotenv from "dotenv";

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, "../.env") });

import { isObjectStorageConfigured, uploadObjectFromFile } from "../src/services/objectStorageService";

const uploadDirs = [
  path.resolve(__dirname, "../uploads/incidents"),
  path.resolve(__dirname, "../uploads/support-issues"),
  path.resolve(__dirname, "../uploads/compliance-packs"),
];

const run = async () => {
  if (!isObjectStorageConfigured()) {
    throw new Error("Object storage is not configured. Set OBJECT_STORAGE_* env vars first.");
  }

  let uploaded = 0;

  for (const dir of uploadDirs) {
    let entries: string[] = [];
    try {
      entries = await fs.readdir(dir);
    } catch (error: any) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }

    for (const entry of entries) {
      const filePath = path.join(dir, entry);
      const stat = await fs.stat(filePath);
      if (!stat.isFile()) continue;

      await uploadObjectFromFile({
        objectKey: path.basename(entry),
        filePath,
      });
      uploaded += 1;
    }
  }

  console.log(`Uploaded ${uploaded} local artifact files to object storage.`);
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
