"""Tests for R2Client with mocked boto3."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pipeline.tools.r2_client import R2Client


@pytest.fixture
def mock_s3():
    """Patch boto3.client and return the mock S3 client."""
    with patch("pipeline.tools.r2_client.boto3.client") as mock_boto:
        mock_client = MagicMock()
        mock_boto.return_value = mock_client
        yield mock_client


@pytest.fixture
def r2_client(mock_s3):
    """Create an R2Client with mocked boto3."""
    return R2Client(
        access_key_id="test-key",
        secret_access_key="test-secret",  # Snyk: test fixture, not a real secret
        endpoint_url="https://test.r2.cloudflarestorage.com",
        bucket_name="test-bucket",
    )


class TestPut:
    def test_calls_put_object_with_correct_params(self, r2_client, mock_s3):
        r2_client.put("sources/test.txt", "hello world", content_type="text/plain")

        mock_s3.put_object.assert_called_once_with(
            Bucket="test-bucket",
            Key="sources/test.txt",
            Body=b"hello world",
            ContentType="text/plain",
        )

    def test_encodes_string_body_to_bytes(self, r2_client, mock_s3):
        r2_client.put("findings/test.txt", "unicode: \u00e9\u00e8\u00ea")

        call_kwargs = mock_s3.put_object.call_args[1]
        assert isinstance(call_kwargs["Body"], bytes)

    def test_accepts_bytes_body_directly(self, r2_client, mock_s3):
        body = b"raw bytes"
        r2_client.put("drafts/test.bin", body, content_type="application/octet-stream")

        call_kwargs = mock_s3.put_object.call_args[1]
        assert call_kwargs["Body"] == b"raw bytes"


class TestGet:
    def test_returns_decoded_content(self, r2_client, mock_s3):
        mock_body = MagicMock()
        mock_body.read.return_value = b"file content here"
        mock_s3.get_object.return_value = {"Body": mock_body}

        result = r2_client.get("reports/test.txt")

        assert result == "file content here"
        mock_s3.get_object.assert_called_once_with(
            Bucket="test-bucket",
            Key="reports/test.txt",
        )


class TestListKeys:
    def test_returns_keys_from_paginator(self, r2_client, mock_s3):
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Contents": [{"Key": "a/1.txt"}, {"Key": "a/2.txt"}]},
            {"Contents": [{"Key": "a/3.txt"}]},
        ]
        mock_s3.get_paginator.return_value = mock_paginator

        keys = r2_client.list_keys(prefix="a/")

        assert keys == ["a/1.txt", "a/2.txt", "a/3.txt"]
        mock_s3.get_paginator.assert_called_once_with("list_objects_v2")

    def test_returns_empty_list_when_no_contents(self, r2_client, mock_s3):
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{}]
        mock_s3.get_paginator.return_value = mock_paginator

        keys = r2_client.list_keys(prefix="empty/")

        assert keys == []


class TestExists:
    def test_returns_true_when_object_exists(self, r2_client, mock_s3):
        mock_s3.head_object.return_value = {}

        assert r2_client.exists("reports/test.txt") is True

    def test_returns_false_when_object_does_not_exist(self, r2_client, mock_s3):
        mock_s3.exceptions.ClientError = type("ClientError", (Exception,), {})
        mock_s3.head_object.side_effect = mock_s3.exceptions.ClientError("Not Found")

        assert r2_client.exists("reports/missing.txt") is False
