# slackNotifyDemo

This is an implementation of [this excellent tutorial](https://aws.amazon.com/blogs/devops/use-slack-chatops-to-deploy-your-code-how-to-integrate-your-pipeline-in-aws-codepipeline-with-your-slack-channel/) with the following changes:

- Secrets encrypted with KMS
- Implemented using [Serverless Framework](https://serverless.com)
- Slack authentication updated to use new [secret signing](https://api.slack.com/docs/verifying-requests-from-slack) instead of the now deprecated verification token

## Usage

Prerequisites: 
- [Install Serverless](https://serverless.com/framework/docs/providers/aws/guide/installation/)
- [Install serverless-kms-secrets](https://github.com/nordcloud/serverless-kms-secrets)
- If you already have node.js and npm installed `npm install`

The secrets are included to demonstrate protecting secrets in public source control. Not recommended

TODO: Write KMS tutorial

TODO: Deploy instructions
