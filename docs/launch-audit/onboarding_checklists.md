# Client / Data / Onboarding Readiness

## Onboarding requirements checklist

- [ ] Customer account owner and billing owner identified
- [ ] Named licensee admin and backup admin identified
- [ ] Named manufacturer contacts identified
- [ ] Approved support contacts and escalation contacts identified
- [ ] Allowed domains and email deliverability checks completed
- [ ] Target geographies and regulatory assumptions documented
- [ ] Required legal documents accepted or contract package sent
- [ ] Connector install prerequisites confirmed for each manufacturer site

## Master data checklist

- [ ] Licensee legal name and operational display name
- [ ] Manufacturer legal name and operational display name
- [ ] Site/location list
- [ ] Product/SKU mapping
- [ ] Batch and QR numbering rules
- [ ] Support contact emails
- [ ] Incident escalation contacts
- [ ] Printer inventory and compatibility details
- [ ] Branding or trust content needed for customer-facing verification pages

## Data import checklist

- [ ] Import template prepared and versioned
- [ ] Required columns documented
- [ ] Allowed values documented
- [ ] Sample import validated in non-production
- [ ] Duplicate handling rule confirmed
- [ ] Rollback plan for bad import confirmed
- [ ] Named importer and approver assigned

## Real-world production data validation checklist

- [ ] Real organization names are correct and approved
- [ ] User email addresses are valid and deliverable
- [ ] Role assignments match contract and operational reality
- [ ] SKU/product references are accurate
- [ ] Batch naming conventions are agreed
- [ ] QR allocation ranges do not overlap
- [ ] Support and escalation contacts are tested
- [ ] Public verification copy is reviewed for customer-safe language

## QR allocation / numbering verification checklist

- [ ] Allocation owner assigned
- [ ] Numbering format approved
- [ ] Prefix/suffix logic validated
- [ ] Collision detection tested
- [ ] Reserved ranges documented
- [ ] Manufacturer handoff format confirmed
- [ ] Audit trail for allocations verified
- [ ] Recovery/reissue procedure documented

## Support readiness checklist

- [ ] Support queue owner assigned
- [ ] Severity definitions agreed
- [ ] Response targets defined
- [ ] Launch-week staffing plan approved
- [ ] Support macros/templates prepared
- [ ] Privacy wording for screenshots/logs approved
- [ ] Escalation path from support to engineering to founder approved
- [ ] Connector install support owner assigned

## Launch-day communications checklist

- [ ] Internal launch room and contacts list prepared
- [ ] Customer-facing launch message approved
- [ ] Incident holding statement approved
- [ ] Support escalation message approved
- [ ] Connector install guidance approved
- [ ] Known issues and workaround note prepared

## Post-launch hypercare checklist

- [ ] Daily review of auth failures
- [ ] Daily review of public verification failures
- [ ] Daily review of support backlog
- [ ] Daily review of connector/printer issues
- [ ] Daily review of QR allocation anomalies
- [ ] Daily review of uptime and alert events
- [ ] 7-day retrospective scheduled

## Where manual operational support will likely be needed

- first licensee setup
- first manufacturer connector installation
- printer compatibility troubleshooting
- onboarding data correction
- support/incident routing during the first week
- QR numbering reconciliation if customer data is messy

## Templates that should exist before launch

- onboarding workbook
- user import template
- manufacturer readiness checklist
- QR allocation approval form
- support escalation matrix
- launch-day contact list
- customer incident update template

## CTO recommendations for a stronger onboarding engine

1. Build a guided onboarding admin flow that captures required data, validates it, and blocks activation until prerequisites are complete.
2. Add import validation reports before commit so customers can fix errors before bad data lands in production.
3. Add a manufacturer readiness scorecard that includes connector trust, printer support, network reachability, and calibration status.
4. Add automatic QR range collision checks and reconciliation reporting as first-class product features.
