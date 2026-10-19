#!/bin/sh
set -eu
aws --endpoint-url http://minio:9000 s3api head-bucket --bucket shop >/dev/null 2>&1 || true
i=0
while ! aws --endpoint-url http://minio:9000 s3 ls s3://shop >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "bucket shop did not appear" >&2
    exit 1
  fi
  sleep 1
done
aws --endpoint-url http://minio:9000 s3api put-bucket-policy --bucket shop --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": ["s3:GetObject"],
    "Resource": ["arn:aws:s3:::shop/*"]
  }]
}'
