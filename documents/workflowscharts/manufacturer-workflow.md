# Manufacturer Workflow

```mermaid
flowchart TD
    A["Sign in as Manufacturer"] --> B["Open Dashboard"]
    B --> C{"Printer already ready?"}
    C -->|No| D["Open Settings"]
    D --> E["Open Printer Setup"]
    E --> F["Printer helper checks this computer"]
    F --> G{"Printer found?"}
    G -->|No| H["Install or reopen printer helper"]
    H --> F
    G -->|Yes| I["MSCQR recommends the safest printer path"]
    I --> J{"Use printer on this computer or save shared printer?"}
    J -->|Use this computer| K["Go back to Batches"]
    J -->|Save shared printer| L["Save printer"]
    L --> M["Print one live test label"]
    M --> N{"Test label confirmed?"}
    N -->|No| O["Open setup help or review printer details"]
    O --> E
    N -->|Yes| P["Go back to Batches"]
    K --> Q["Open My Batches"]
    P --> Q
    Q --> R["Choose allocated batch"]
    R --> S["Start print run"]
    S --> T{"Saved printer ready?"}
    T -->|No| U["Open Printer Setup and refresh printers"]
    U --> E
    T -->|Yes| V["Confirm quantity"]
    V --> W["MSCQR sends print run"]
    W --> X["Printer helper or saved printer confirms completion"]
    X --> Y{"Print finished?"}
    Y -->|No| Z["Resume active print run instead of starting a duplicate"]
    Z --> W
    Y -->|Yes| AA["Labels marked printed"]
    AA --> AB["Customer can scan labels later"]
```

## Notes

- Manufacturers stay inside the normal batch workflow after setup.
- Duplicate print runs are blocked by design.
- A label is only marked printed after printer confirmation.
