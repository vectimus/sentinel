"""Cloudflare R2 client via S3-compatible API (boto3)."""

from __future__ import annotations

import boto3
from botocore.config import Config as BotoConfig


class R2Client:
    """Client for Cloudflare R2 object storage."""

    def __init__(
        self,
        access_key_id: str,
        secret_access_key: str,
        endpoint_url: str,
        bucket_name: str = "vectimus-research-archive",
    ) -> None:
        self.bucket_name = bucket_name
        self._s3 = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            config=BotoConfig(
                signature_version="s3v4",
                retries={"max_attempts": 3, "mode": "adaptive"},
            ),
        )

    def put(self, key: str, body: str | bytes, content_type: str = "text/plain") -> None:
        """Upload an object to R2."""
        if isinstance(body, str):
            body = body.encode("utf-8")
        self._s3.put_object(
            Bucket=self.bucket_name,
            Key=key,
            Body=body,
            ContentType=content_type,
        )

    def get(self, key: str) -> str:
        """Download an object from R2 and return as string."""
        response = self._s3.get_object(Bucket=self.bucket_name, Key=key)
        return response["Body"].read().decode("utf-8")

    def list_keys(self, prefix: str = "") -> list[str]:
        """List object keys under a prefix."""
        paginator = self._s3.get_paginator("list_objects_v2")
        keys = []
        for page in paginator.paginate(Bucket=self.bucket_name, Prefix=prefix):
            for obj in page.get("Contents", []):
                keys.append(obj["Key"])
        return keys

    def exists(self, key: str) -> bool:
        """Check if an object exists."""
        try:
            self._s3.head_object(Bucket=self.bucket_name, Key=key)
            return True
        except self._s3.exceptions.ClientError:
            return False
