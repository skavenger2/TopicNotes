# Get You Head into the Cloud

BHIS Webcast by Sean Verity

## Amzaon Cognito

Cognito gives you creds
AccessKeyId, SecetKey and SessionToken  
Manually configure AWS-CLI to input the temporary session token  
Verify, Audit, then escalate  

```bash
aws sts-get-caller-identity
python ./aws_service_enum.py --access key <access-key> --secret_key <secrect-key> --session-token <sess-token>
aws iam create-access-key --user AWSCloudAdmin
```

## AWS AppStream

Similar to Citrix Virtual App  
Perform a env breakout  
use a command prompt to request metadata endpoint to access AWS access keys  

## Finding AWS S3 buckets

JS Miner can find them  
Search burp for "aws.amazon.com  
