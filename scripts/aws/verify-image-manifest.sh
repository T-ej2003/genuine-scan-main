#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/aws/verify-image-manifest.sh <image-uri>

Inspect a pushed image manifest with docker buildx imagetools inspect and fail if
required platforms are missing.

Environment:
  REQUIRED_PLATFORMS  Comma-separated required platforms. Default: linux/amd64

Example:
  REQUIRED_PLATFORMS=linux/amd64,linux/arm64 \
    ./scripts/aws/verify-image-manifest.sh \
    123456789012.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend:$(git rev-parse HEAD)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

IMAGE_URI="${1:-}"
if [[ -z "$IMAGE_URI" ]]; then
  usage >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to inspect image manifests." >&2
  exit 1
fi

RAW_FILE="$(mktemp)"
TEXT_FILE="$(mktemp)"
trap 'rm -f "$RAW_FILE" "$TEXT_FILE"' EXIT

docker buildx imagetools inspect --raw "$IMAGE_URI" >"$RAW_FILE"
docker buildx imagetools inspect "$IMAGE_URI" >"$TEXT_FILE"

REQUIRED_PLATFORMS="${REQUIRED_PLATFORMS:-linux/amd64}"

node --input-type=module - "$IMAGE_URI" "$RAW_FILE" "$TEXT_FILE" "$REQUIRED_PLATFORMS" <<'NODE'
import fs from "node:fs";

const [imageUri, rawPath, textPath, requiredText] = process.argv.slice(2);
const required = requiredText
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

const raw = JSON.parse(fs.readFileSync(rawPath, "utf8"));
let platforms = [];

if (Array.isArray(raw.manifests)) {
  platforms = raw.manifests
    .map((manifest) => {
      const platform = manifest?.platform || {};
      if (!platform.os || !platform.architecture) return null;
      if (platform.os === "unknown" || platform.architecture === "unknown") return null;
      return [platform.os, platform.architecture, platform.variant].filter(Boolean).join("/");
    })
    .filter(Boolean);
}

if (!platforms.length) {
  const text = fs.readFileSync(textPath, "utf8");
  platforms = [...text.matchAll(/Platform:\s+([^\s]+)/g)]
    .map((match) => match[1])
    .filter((platform) => platform !== "unknown/unknown");
}

platforms = [...new Set(platforms)].sort();

if (!platforms.length) {
  console.error(`Unable to determine any platforms for ${imageUri}.`);
  process.exit(1);
}

const missing = required.filter(
  (requiredPlatform) =>
    !platforms.some(
      (platform) => platform === requiredPlatform || platform.startsWith(`${requiredPlatform}/`)
    )
);

console.log(`Image: ${imageUri}`);
console.log(`Platforms: ${platforms.join(", ")}`);

if (missing.length) {
  console.error(`Missing required platforms: ${missing.join(", ")}`);
  process.exit(1);
}

console.log(`Verified required platforms: ${required.join(", ")}`);
NODE
