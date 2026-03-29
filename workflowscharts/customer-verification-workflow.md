# Customer Verification Workflow

```mermaid
flowchart TD
    A["Scan QR code on product"] --> B["Open MSCQR verification page"]
    B --> C["MSCQR checks product code, signature, and latest status"]
    C --> D{"Verification result"}
    D -->|Trusted match| E["Show genuine product result"]
    D -->|Needs caution| F["Show warning and guidance"]
    D -->|Blocked or invalid| G["Show risk result and support path"]
    E --> H["Customer sees product details and confidence message"]
    F --> I["Customer sees what to check next"]
    G --> J["Customer sees report or support option"]
    H --> K["Optional: view product journey or support info"]
    I --> K
    J --> K
```

## Notes

- The customer flow should stay simple and trust-focused.
- The page explains the result, not the backend mechanics.
- If the result is risky, the customer gets a clear next step instead of a technical error.
