# S3 storage

Stores objects in an S3-compatible bucket. Preserved only by `easyrest-server` (`cmd/server` registers the factory). `easyrest-gateway` needs `easyrest-storage-s3` or a `path`. `Init` creates the bucket when `HeadBucket` returns 404. A region other than `us-east-1` sends `LocationConstraint` on create.

| Key | Default | Meaning |
| --- | --- | --- |
| `endpoint` | empty | Base URL. Required for MinIO, Ceph RGW, and OpenStack. Empty for AWS |
| `region` | `us-east-1` | Region for the client and for `LocationConstraint` when it is not `us-east-1` |
| `bucket` | required | Bucket name |
| `prefix` | empty | Key prefix inside the bucket. It is not part of the path `Put` returns |
| `access_key` | required | Static access key |
| `secret_key` | required | Static secret key |
| `path_style` | `true` when `endpoint` is set and this key is omitted, otherwise `false` | Path-style addressing |
| `public_base` | empty | Origin without a trailing slash. `GetUrl` returns `public_base` plus the object key |
| `inline` | false | `true` makes `Put` return a data URL. The column and the response are that string |

Without `public_base`, `GetUrl` returns path-style `{endpoint}/{bucket}/{key}`, or `https://{bucket}.s3.{region}.amazonaws.com/{key}` when `endpoint` is empty.

```yaml
storage_plugins:
  photos:
    plugin: s3
    settings:
      endpoint: http://minio:9000
      region: us-east-1
      bucket: media
      prefix: photos
      access_key: minio
      secret_key: minio-secret
      path_style: true
  cdn:
    plugin: s3
    settings:
      endpoint: http://minio:9000
      region: us-east-1
      bucket: media
      prefix: public
      access_key: minio
      secret_key: minio-secret
      public_base: https://cdn.example.com
```

Which REST action uses which instance is in [Configuration](../../../internal/config/README.md#application-and-restapi).

## See also

- [Server README](../../../README.md)
- [Local](../local/README.md)
- [Plugin SDK](../../../plugin/README.md)
