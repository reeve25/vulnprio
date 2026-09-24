"""Persistence: raw uploads in S3, scans + ranked findings in one DynamoDB table.

Table layout (single table, on-demand):
  PK=SCANS          SK={created_at}#{scan_id}     scan index, newest last
  PK=SCAN#{id}      SK=META                       scan summary
  PK=SCAN#{id}      SK=F#{priority}#{rank:05d}    one item per finding, JSON in `d`

Putting the priority in the sort key makes `?priority=P1` a begins_with key
condition, so Limit + cursor pagination stays correct without a GSI.
"""

import base64
import json
import os
import time
from dataclasses import asdict

import boto3
from boto3.dynamodb.conditions import Key

from .parsers import Finding

TTL_DAYS = 90  # matches the S3 lifecycle rule in infra/


def _cursor_encode(key: dict | None) -> str | None:
    return base64.urlsafe_b64encode(json.dumps(key).encode()).decode() if key else None


def _cursor_decode(cursor: str | None, scan_id: str) -> dict | None:
    if not cursor:
        return None
    try:
        key = json.loads(base64.urlsafe_b64decode(cursor.encode()))
    except (ValueError, TypeError):
        raise ValueError("invalid cursor") from None
    # Only accept keys for this scan's findings, so a cursor can't be used to read other partitions.
    if (
        not isinstance(key, dict)
        or set(key) != {"PK", "SK"}
        or key["PK"] != f"SCAN#{scan_id}"
        or not str(key["SK"]).startswith("F#")
    ):
        raise ValueError("invalid cursor")
    return key


class Store:
    def __init__(self, table: str | None = None, bucket: str | None = None, endpoint_url: str | None = None):
        endpoint_url = endpoint_url or os.environ.get("AWS_ENDPOINT_URL") or None
        self.table = boto3.resource("dynamodb", endpoint_url=endpoint_url).Table(
            table or os.environ.get("VULNPRIO_TABLE", "vulnprio")
        )
        self.s3 = boto3.client("s3", endpoint_url=endpoint_url)
        self.bucket = bucket or os.environ.get("VULNPRIO_BUCKET", "vulnprio-raw")

    def save_scan(self, meta: dict, findings: list[Finding], raw: bytes) -> None:
        """Write raw upload, then findings, then META + index last.

        Ordering means a crash mid-ingest leaves orphaned findings (expired by
        TTL) but never a listed scan with missing findings.
        """
        scan_id = meta["scan_id"]
        expires = int(time.time()) + TTL_DAYS * 86400
        self.s3.put_object(Bucket=self.bucket, Key=f"raw/{scan_id}", Body=raw)
        with self.table.batch_writer() as batch:  # handles 25-item chunks and UnprocessedItems retries
            for rank, f in enumerate(findings):
                batch.put_item(
                    Item={
                        "PK": f"SCAN#{scan_id}",
                        "SK": f"F#{f.priority}#{rank:05d}",
                        "d": json.dumps(asdict(f)),
                        "ttl": expires,
                    }
                )
        self.table.put_item(Item={"PK": f"SCAN#{scan_id}", "SK": "META", "d": json.dumps(meta), "ttl": expires})
        self.table.put_item(
            Item={"PK": "SCANS", "SK": f"{meta['created_at']}#{scan_id}", "d": json.dumps(meta), "ttl": expires}
        )

    def list_scans(self, limit: int = 50) -> list[dict]:
        # ponytail: single PK=SCANS partition caps at ~1000 writes/s; shard by day if ingest ever gets there
        resp = self.table.query(KeyConditionExpression=Key("PK").eq("SCANS"), ScanIndexForward=False, Limit=limit)
        return [json.loads(i["d"]) for i in resp["Items"]]

    def get_scan(self, scan_id: str) -> dict | None:
        item = self.table.get_item(Key={"PK": f"SCAN#{scan_id}", "SK": "META"}).get("Item")
        return json.loads(item["d"]) if item else None

    def get_findings(
        self, scan_id: str, priority: str | None = None, limit: int = 100, cursor: str | None = None
    ) -> tuple[list[dict], str | None]:
        prefix = f"F#{priority}#" if priority else "F#"
        kwargs = {
            "KeyConditionExpression": Key("PK").eq(f"SCAN#{scan_id}") & Key("SK").begins_with(prefix),
            "Limit": limit,
        }
        if start := _cursor_decode(cursor, scan_id):
            kwargs["ExclusiveStartKey"] = start
        resp = self.table.query(**kwargs)
        return [json.loads(i["d"]) for i in resp["Items"]], _cursor_encode(resp.get("LastEvaluatedKey"))
