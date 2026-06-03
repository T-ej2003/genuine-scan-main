# Publishing To GitHub

Do this later from the parent repository root. Do not run these commands until the project is ready to publish.

```bash
mkdir aws-webapp-cost-optimizer
cp -R tools/aws-webapp-cost-optimizer/* aws-webapp-cost-optimizer/
cd aws-webapp-cost-optimizer
git init
git add .
git commit -m "Initial AWS webapp cost optimizer"
gh repo create T-ej2003/aws-webapp-cost-optimizer --public --source=. --remote=origin --push
```

Do not commit generated evidence, secrets, tokens, private keys, `.env` files, or raw credentials.
