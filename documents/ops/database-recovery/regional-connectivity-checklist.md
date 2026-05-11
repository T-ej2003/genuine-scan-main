# Regional Database Connectivity Checklist

Last updated: 2026-05-11

## Mumbai App To Recovered DB

- [ ] Mumbai target DB endpoint identified.
- [ ] DNS resolves from Mumbai app server.
- [ ] Security group allows Mumbai app server ingress.
- [ ] Subnet/routing path is approved.
- [ ] SSL/TLS DB connection requirements are configured if applicable.
- [ ] Backend can connect without exposing credentials.
- [ ] `/api/health/ready` reports database ready.
- [ ] Backend logs inspected for DB errors.

## Cape Town App To Recovered DB

- [ ] Cape Town target DB endpoint identified.
- [ ] DNS resolves from Cape Town app server.
- [ ] Security group allows Cape Town app server ingress.
- [ ] Subnet/routing path is approved.
- [ ] SSL/TLS DB connection requirements are configured if applicable.
- [ ] Backend can connect without exposing credentials.
- [ ] `/api/health/ready` reports database ready.
- [ ] Backend logs inspected for DB errors.

## Shared Network Checks

- [ ] DB endpoint uses approved network path.
- [ ] No public exposure unless explicitly approved.
- [ ] Security groups are least privilege.
- [ ] Routing tables allow only intended access.
- [ ] DNS/endpoint name is documented.
- [ ] TLS mode is documented.

## Logs To Inspect

- Backend startup logs.
- Backend health-check logs.
- Database connection/authentication logs where available.
- Security group or VPC flow logs where available.

## Pass/Fail Table

| Region | DB endpoint | Connectivity | Ready endpoint | Logs clean | Owner | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Mumbai |  |  |  |  |  |  |
| Cape Town |  |  |  |  |  |  |
