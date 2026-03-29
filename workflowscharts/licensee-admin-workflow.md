# Licensee Admin Workflow

```mermaid
flowchart TD
    A["Sign in as Licensee Admin"] --> B["Pass MFA if required"]
    B --> C["Open Dashboard"]
    C --> D["Review code requests, manufacturers, and batch status"]
    D --> E{"Need new QR inventory?"}
    E -->|Yes| F["Create or approve code request"]
    F --> G["Track issued QR ranges"]
    E -->|No| H["Continue operations"]
    G --> H
    H --> I{"Need to assign work to manufacturer?"}
    I -->|Yes| J["Open Manufacturers or Batches"]
    J --> K["Assign or update manufacturer access"]
    K --> L["Create or update batch allocation"]
    I -->|No| M["Monitor batch progress"]
    L --> M
    M --> N{"Manufacturer reports a printer issue?"}
    N -->|Yes| O["Guide manufacturer to Settings and Printer Setup"]
    O --> P["Review support notes or open help guidance"]
    P --> M
    N -->|No| Q["Continue monitoring"]
    Q --> R{"Need audit or trace review?"}
    R -->|Yes| S["Open Audit History or Scan Activity"]
    S --> T["Review scans, usage, and exceptions"]
    R -->|No| U["Wait for next action"]
    T --> U
```

## Notes

- Licensee admins manage manufacturers, batches, and QR allocation.
- They do not print labels themselves unless the business process allows it.
- Sensitive changes still require fresh verification where applicable.
