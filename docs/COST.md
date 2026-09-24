# Cost estimate (us-east-1, on-demand list prices)

This file was written before deployment. The "demo traffic" section below uses per-request numbers measured on a
real deployment. Prices are list prices as of writing; check <https://aws.amazon.com/pricing/> before relying on them.

## Demo traffic, from numbers measured on 2026-09-24 (us-west-2)

The deployed stack (DECISIONS #9) was billed **35.2 GB-s for 341 invocations** at 1 GB. It wrote **~709 items per scan**
(11,315 findings plus metadata across 16 scans), and the image in ECR was **75 MB**. Scaled to a demo month of
100 scans + 1,000 reads:

| Line item | Monthly |
|---|---|
| Lambda (100 × 0.62 s + 1,000 × ~0.05 s ≈ 112 GB-s; 1,100 requests) | $0.002 |
| API Gateway (1,100 requests) | $0.001 |
| DynamoDB writes (~71k WRU, assuming items ≤ 1 KB) + storage + PITR | ≈ $0.13 |
| S3, ECR (75 MB), X-Ray, logs | ≈ $0.01 |
| KMS key | $1.00 |
| CloudWatch: dashboard $3.00, 5 custom metrics $1.50, 5 alarms (6 metrics) $0.60 | $5.10 |
| **Total, list price** | **≈ $6.25** |
| **Total, after always-free tiers** (first 3 dashboards, 10 metrics, 10 alarms, 1M Lambda requests) | **≈ $1.15**, mostly the KMS key |

The ~2 hours the stack actually ran cost a few cents (prorated KMS plus a few thousand DynamoDB writes). Cost Explorer
lags about 24 h, so that figure is estimated, not billed. The $5/month AWS Budget (50%/100% actual, 100% forecast
email alerts) stays in place. Unit prices are the us-east-1 list prices from the table below, not re-checked for us-west-2.

## Assumptions for the busy month
- 1,000 scans/month, ~500 findings each, raw upload ~1 MB. Plus ~4,000 read requests (GET scan/findings).
- Ingest ~3 s warm at 1 GB memory (enrichment cached in-process, DECISIONS #6); GETs ~100 ms.
- A finding item is ≤ 1 KB, so each costs 1 write unit. With the 90-day TTL/lifecycle, storage settles at about 3 months of data.

## Monthly estimate

| Line item | Price | (a) Idle | (b) 1,000 scans × 500 findings | Always-free / 12-mo free tier |
|---|---|---|---|---|
| Lambda requests | $0.20 / 1M | $0 | 5,000 × $0.20/1M = **$0.001** | 1M req/mo (always) |
| Lambda compute (x86) | $0.0000166667 / GB-s | $0 | (1,000 × 3 GB-s + 4,000 × 0.1 GB-s) = 3,400 GB-s → **$0.06** | 400k GB-s/mo (always) |
| API Gateway HTTP API | $1.00 / 1M | $0 | 5,000 → **$0.005** | 1M/mo (12 mo) |
| DynamoDB writes (on-demand) | $0.625 / 1M WRU | $0 | 1,000 × 502 items = 502k WRU → **$0.31** | — |
| DynamoDB reads | $0.125 / 1M RRU | $0 | 4,000 × ~10 RRU (100 items × ~0.8 KB, eventually consistent) = 40k → **$0.005** | — |
| DynamoDB storage | $0.25 / GB-mo | $0 | 3 mo × 500k items × 1 KB ≈ 1.5 GB → **$0.38** | 25 GB (always) |
| DynamoDB PITR | $0.20 / GB-mo | $0 | 1.5 GB → **$0.30** | — |
| S3 storage | $0.023 / GB-mo | $0 | ~3 GB (3 months × 1 GB) → **$0.07** | 5 GB (12 mo) |
| S3 PUT | $0.005 / 1k | $0 | 1,000 → **$0.005** | 2k PUT (12 mo) |
| KMS CMK | $1 / key-mo | **$1.00** | **$1.00** | — (rotation adds $1/mo per rotation, capped at 2: up to $3/mo from year 3) |
| KMS requests | $0.03 / 10k | $0 | < 20k (S3 bucket key + DynamoDB key caching) → **$0** | 20k/mo (always) |
| CloudWatch Logs ingest | $0.50 / GB | $0 | ~5,000 × 2 KB (app + REPORT + access log) ≈ 10 MB → **$0.005** | 5 GB (always) |
| CloudWatch custom metrics (EMF) | $0.30 / metric-mo | $0 (billed only while emitted) | 5 metrics → **$1.50** | 10 metrics (always) |
| CloudWatch alarms | $0.10 / metric-mo | **$0.60** | **$0.60** (4 × $0.10 + the 5xx-rate alarm counts 2 metrics = $0.20) | 10 alarms (always) |
| CloudWatch dashboard | $3 / dashboard-mo | **$3.00** | **$3.00** | first 3 dashboards (always) |
| ECR storage | $0.10 / GB-mo | **$0.15** | **$0.15** (≤ 10 images × ~150 MB, lifecycle policy) | 500 MB (12 mo) |
| X-Ray traces | $5 / 1M | $0 | 5,000 → **$0.03** | 100k traces/mo (always) |
| SNS email | — | $0 | $0 | 1,000 emails/mo (always) |
| **Total, list price** | | **≈ $4.75** | **≈ $7.50** | |
| **Total, after always-free tiers** | | **≈ $1.15** (KMS + ECR) | **≈ $2.25** (KMS, DynamoDB writes/storage/PITR, S3, ECR) | |

The busy month is dominated by fixed costs (the KMS key and the dashboard). Per scan, the variable cost is about
$0.0007, mostly the 500 DynamoDB writes.

## Alternatives rejected (DECISIONS #3, #4)

| Design | Always-on monthly cost | Arithmetic |
|---|---|---|
| **This design** (Lambda + HTTP API + DynamoDB) | **≈ $1–5 idle** | table above |
| Fargate + ALB | **≈ $45** | Fargate 0.5 vCPU/1 GB: (0.5 × $0.04048 + 1 × $0.004445) × 730 h = $18.02; ALB $0.0225 × 730 = $16.43 + ~1 LCU $0.008 × 730 = $5.84; public IPv4 $0.005/h × 730 = $3.65 each (2 for the ALB) = $7.30 |
| Lambda in a VPC + RDS Postgres + NAT | **≈ $50** | db.t4g.micro $0.016 × 730 = $11.68 + 20 GB gp3 × $0.115 = $2.30; NAT gateway $0.045 × 730 = $32.85 + $0.045/GB processed; NAT's public IPv4 $3.65. The NAT is needed because enrichment calls CISA/FIRST/NVD over the internet |

Both alternatives bill 24/7 whether or not a scan arrives. Even at 1,000 scans/month, this design costs about 5% of either one.
