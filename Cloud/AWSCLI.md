# AWSCLI Commands

## List buckets  

```bash
# All available
aws s3 ls

# For a profile
aws s3 ls

# For a bucket
aws s3 ls s3://<bucket-name [--profile <aws-profile> ]
```

## Mutliple AWS profiles  

In `~/.aws/credentials` you can use different sets of keys  

```bash
[default]
[default]
aws_access_key_id = <key>
aws_secret_access_key = <key>

[second-profile]
aws_access_key_id = <key>
aws_secret_access_key = <key>
```

Specify other keys with  
`aws <commands> --profile second-profile`  
