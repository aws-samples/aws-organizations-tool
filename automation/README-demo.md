# command list for the demo

- `aws sts get-caller-identity | jq -r . `
- result >
  ```
  {
      "UserId": "AIDAWHX3UAKSJ6SFOGKHS",
      "Account": "428950684324",
      "Arn": "arn:aws:iam::428950684324:user/laurent"
  }
  ```
- `bash init-deploy.sh -r Org_Provisioning`
