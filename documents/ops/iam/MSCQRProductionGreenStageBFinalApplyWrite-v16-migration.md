# FinalApplyWrite v16 one-way predecessor migration

Production policy `arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBFinalApplyWrite` version `v16` was created as the default by the governed root identity at `2026-08-24T00:23:24Z`. Its canonical compact SHA-256 is `4b2a7d59601eae34f9ab9b9c6ce7a211eee13460fd45774594ed964cd60e05c6`.

The document exactly matches policy source commit `b5e5851076ddf1acfcab7c107ff17b46cb057479` with the activation target bound to backend candidate revision `7`. Commit `39163780fa8c79f34460ff766315a87df3913b62` later added the exact broker-policy ownership DynamoDB statement. No other semantic difference exists between live v16 and its historical source.

The migration predicate is separate from ordinary normal-activation validation. It accepts only the exact v16 document and five-version topology, the exact serial-115 binding, current protected main descended from `24bec15c546299907fed35fe84176f931c68edd7`, backend SOURCE revision `24`, and backend TARGET revision `27`. The successor is the ordinary protected-main transaction policy and must include the exact broker-ownership authority. After that version becomes default, ordinary strict validation applies and v16 cannot be selected as a successor.

The migration requires the canonical serial-115 binding file and its exact SHA-256 `2f575ae3b5fc5d944dffe3d70d02d7b2202b7b4d8e73e60798976cb8675c4710`. It does not authorize an IAM write; production convergence still requires a separately reviewed mutation boundary.
