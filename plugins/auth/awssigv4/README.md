# AWS Signature Version 4

Parses an AWS SigV4 `Authorization` header. `easyrest-server` keeps it in-process. The external binary is `easyrest-auth-awssigv4`.

| Key | Default | Meaning |
| --- | --- | --- |
| `aws_access_key_id` | empty | Access key used to check the signature |
| `aws_secret_access_key` | empty | Secret used to check the signature |

When both keys are non-empty, the plugin checks the signature. When either is missing, it only parses the header and still returns claims.

The header must look like:

```
AWS4-HMAC-SHA256 Credential=<AccessKeyID>/<Date>/<Region>/<Service>/aws4_request, SignedHeaders=<headers>, Signature=<sig>
```

Claims include `access_key_id`, `date_stamp`, `region`, `service`, `signed_headers`, `signature`, `full_header`, and `scope`. `scope` is the service name from the credential, not `read` or `write`.

Swagger is `apiKey` on the `Authorization` header.

```yaml
auth_plugins:
  awssigv4:
    settings:
      aws_access_key_id: AKIAEXAMPLE
      aws_secret_access_key: secret
```

Omit both keys to accept a well-formed header without checking the signature.

Trial order is in [Auth and scopes](../../../internal/server/README.md#auth-and-scopes).

## See also

- [Server README](../../../README.md)
- [Plugin SDK](../../../plugin/README.md)
