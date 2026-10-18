#!/usr/bin/env python3
"""Cross-check the H1 report IDs we plan to use against the independent reddelexc archive."""
import csv, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))

# report IDs we intend to use (from agent digests, QUALITY: good)
planned = {
    # sqli
    150156: "Uber sctrack base64 sleep(12) blind",
    273946: "Grab drivegrab order_by shortcode",
    298176: "GitLab MilestoneFinder order CASE (CVE-2017-0914)",
    838855: "Zomato geto2banner res_id CASE WHEN SLEEP",
    836079: "Zomato widgets_handler res_id CASE WHEN SLEEP",
    # ssrf
    398799: "GitLab Jira oauth Host header",
    776017: "Kubernetes StorageClass resturl (CVE-2020-8555)",
    374737: "H1 errors.hackerone.net Sentry filename",
    1628209: "DoD FAST pdf generator iframe metadata",
    1960765: "Reddit matrix preview_url og:title",
    826361: "GitLab Note remote_attachment_url",
    # idor
    2207248: "Shopify GraphQL BillingDocumentDownload",
    1658418: "Reddit gql mod logs subredditName",
    3862641: "HackerOne reference.json error-body leak",
    1213237: "RedditGifts DELETE DM",
    743953: "GitLab project import issue_ids",
    1819832: "Snapchat DeleteStorySnaps ids",
    # open redirect
    904059: "Rails actionable exceptions location (CVE-2020-8264)",
    104087: "Slack checkcookie redir SVG",
    635597: "Twitter unsafe_link RTLO punycode",
    683298: "MoPub login next=",
    1788006: "Expedia ?logout=",
    49759:  "mobile.twitter.com messages/follow recipient",
}

found = {}
with open(os.path.join(HERE, "reddelexc.csv"), encoding="utf-8", errors="replace") as fh:
    for row in csv.DictReader(fh):
        try:
            rid = int(row["link"].rsplit("/", 1)[1])
        except (ValueError, IndexError, KeyError):
            continue
        if rid in planned:
            found[rid] = (row["title"], row.get("vuln_type", ""), row.get("bounty", ""))

print(f"planned: {len(planned)} | independently confirmed: {len(found)}")
for rid, why in planned.items():
    if rid in found:
        t, vt, b = found[rid]
        print(f"  OK   {rid}: {t[:70]} | {vt} | ${b}")
    else:
        print(f"  MISS {rid}: {why}")

missing = [rid for rid in planned if rid not in found]
print("\nnot in reddelexc archive:", missing)
