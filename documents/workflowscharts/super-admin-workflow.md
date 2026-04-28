# Super Admin Workflow

```mermaid
flowchart TD
    A["Sign in as Super Admin"] --> B["Complete MFA or security-key check"]
    B --> C["Open Dashboard"]
    C --> D{"What needs attention?"}

    D -->|Tenant or access setup| E["Open Licensees or Manufacturers"]
    E --> F["Create, update, invite, or restrict access"]
    F --> G["Audit the change"]

    D -->|QR supply and operations| H["Open Code Requests or Batches"]
    H --> I["Approve requests, review allocations, and watch print progress"]
    I --> G

    D -->|Live risk or abuse signal| J["Open Incident Response"]
    J --> K["Review alert, investigate evidence, and take action"]
    K --> L{"Needs policy or platform control change?"}
    L -->|Yes| M["Open Settings"]
    M --> N["Open System Controls"]
    N --> O{"High-risk change?"}
    O -->|Yes| P["Submit approval request"]
    P --> Q["Second approver reviews and confirms"]
    Q --> R["Apply approved change"]
    O -->|No| R
    R --> G
    L -->|No| G

    D -->|Customer or partner issue| S["Open Support"]
    S --> T["Review ticket, diagnostics, and evidence"]
    T --> U{"Need escalation?"}
    U -->|Yes| J
    U -->|No| G

    G --> V["Review audit trail and notifications"]
    V --> W["Close the loop with the team"]
```

## Notes

- Super Admin owns platform-wide access, incident response, and governance.
- The highest-risk changes can require two-person approval.
- Audit and evidence review are part of the normal workflow, not an afterthought.
