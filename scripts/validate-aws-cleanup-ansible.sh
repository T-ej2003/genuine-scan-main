#!/bin/bash
set -euo pipefail

required_files=(
  "ansible/aws-cleanup/regions.yml"
  "playbooks/aws-cleanup/regional_inventory.yml"
  "playbooks/aws-cleanup/README.md"
)

for file in "${required_files[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "Missing required file: $file" >&2
    exit 1
  fi
done

ansible-playbook --syntax-check playbooks/aws-cleanup/regional_inventory.yml

echo "AWS cleanup Ansible inventory validation passed."
