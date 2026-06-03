# Roadmap

## Next Best Features

1. Add CloudWatch metric adapters for EC2 CPU/network, RDS CPU/memory/IOPS/connections, ElastiCache CPU/memory/evictions/connections, NAT bytes, and ALB request/5xx counts.
2. Add Cost Explorer import and service/usage-type normalization.
3. Add policy files for organization-specific keep rules.
4. Add HTML report output with evidence links and risk filters.
5. Add an approval-record schema that can be signed and stored separately.
6. Add CI checks for mutation keyword regression and gitleaks.

## Scalability Recommendations

- Keep collectors stateless and region-parallelizable.
- Store evidence as append-only timestamped directories.
- Use typed resource adapters instead of ad hoc string matching.
- Keep mutation planning in a separate package if it is ever added.
