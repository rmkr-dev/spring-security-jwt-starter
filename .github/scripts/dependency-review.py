#!/usr/bin/env python3
"""Fail when a pull request adds a dependency with a known moderate or higher vulnerability.

Compares CycloneDX ``bom.json`` files under a base directory and a head directory.
Only packages present at head and absent at base are queried against the OSV API.
"""

import json
import math
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

OSV_URL = "https://api.osv.dev/v1/querybatch"
BATCH = 200
FAIL_FROM = 2
RANK = {"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CVSS_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},
}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def round_half_up(value):
    return math.floor(value + 0.5)


def cvss_roundup(value):
    """CVSS v3.1 Roundup: smallest number with one decimal place that is >= value."""
    scaled = round_half_up(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def cvss_v3_base(vector):
    """Return the CVSS v3 base score, or None when the vector is not v3."""
    if not vector.startswith("CVSS:3."):
        return None
    metrics = {}
    for part in vector.split("/")[1:]:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key] = value
    try:
        scope = metrics["S"]
        av = CVSS_V3["AV"][metrics["AV"]]
        ac = CVSS_V3["AC"][metrics["AC"]]
        ui = CVSS_V3["UI"][metrics["UI"]]
        confidentiality = CVSS_V3["C"][metrics["C"]]
        integrity = CVSS_V3["I"][metrics["I"]]
        availability = CVSS_V3["A"][metrics["A"]]
        pr = (PR_CHANGED if scope == "C" else PR_UNCHANGED)[metrics["PR"]]
    except KeyError:
        return None
    impact_sub = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    if scope == "U":
        impact = 6.42 * impact_sub
    elif scope == "C":
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * ((impact_sub - 0.02) ** 15)
    else:
        return None
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope == "U":
        base = min(impact + exploitability, 10)
    else:
        base = min(1.08 * (impact + exploitability), 10)
    return cvss_roundup(base)


def advisory_rank(vuln):
    """Return (label, rank). Rank >= 2 fails the pull request."""
    text = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(text, str) and text.upper() in RANK:
        label = text.upper()
        return label, RANK[label]
    scores = []
    saw_v4 = False
    for item in vuln.get("severity") or []:
        score = item.get("score") or ""
        kind = item.get("type") or ""
        if kind == "CVSS_V4" or score.startswith("CVSS:4."):
            saw_v4 = True
        parsed = cvss_v3_base(score)
        if parsed is not None:
            scores.append(parsed)
    if scores:
        best = max(scores)
        if best >= 9.0:
            label = "CRITICAL"
        elif best >= 7.0:
            label = "HIGH"
        elif best >= 4.0:
            label = "MODERATE"
        else:
            label = "LOW"
        return label, RANK[label]
    if saw_v4:
        return "MODERATE", FAIL_FROM
    return "UNKNOWN", FAIL_FROM


def purl_of(component):
    purl = component.get("purl") or ""
    if not purl.startswith("pkg:"):
        return None
    return purl.split("?", 1)[0].split("#", 1)[0]


def load_purls(root):
    purls = set()
    found = False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in {".git"}]
        if "bom.json" not in filenames:
            continue
        found = True
        path = os.path.join(dirpath, "bom.json")
        with open(path, encoding="utf-8") as handle:
            bom = json.load(handle)
        for component in bom.get("components") or []:
            purl = purl_of(component)
            if purl:
                purls.add(purl)
    if not found:
        raise SystemExit(f"no bom.json under {root}")
    return purls


def query_osv(purls):
    # querybatch returns ids only. The vulnerability document carries the severity.
    ordered = sorted(purls)
    ids_by_purl = {}
    unique_ids = []
    seen = set()
    for start in range(0, len(ordered), BATCH):
        chunk = ordered[start:start + BATCH]
        body = json.dumps({"queries": [{"package": {"purl": purl}} for purl in chunk]}).encode()
        payload = request_json(OSV_URL, body)
        results = payload.get("results") or []
        if len(results) != len(chunk):
            raise SystemExit("OSV returned a different number of results than queries")
        for purl, result in zip(chunk, results):
            idents = []
            for vuln in result.get("vulns") or []:
                ident = vuln.get("id")
                if not ident:
                    continue
                idents.append(ident)
                if ident not in seen:
                    seen.add(ident)
                    unique_ids.append(ident)
            ids_by_purl[purl] = idents
    details = {
        ident: request_json("https://api.osv.dev/v1/vulns/" + urllib.parse.quote(ident, safe=""))
        for ident in unique_ids
    }
    found = {}
    for purl, idents in ids_by_purl.items():
        vulns = []
        for ident in idents:
            vuln = details[ident]
            if vuln.get("withdrawn"):
                continue
            label, rank = advisory_rank(vuln)
            if rank >= FAIL_FROM:
                vulns.append((ident, label))
        if vulns:
            found[purl] = sorted(set(vulns))
    return found


def request_json(url, body=None):
    delay = 2
    last_error = None
    for _attempt in range(4):
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "entra-security-dependency-review"},
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            last_error = error
            if error.code < 500 and error.code != 429:
                raise SystemExit(f"OSV query failed: HTTP {error.code} for {url}") from error
            time.sleep(delay)
            delay *= 2
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            last_error = error
            time.sleep(delay)
            delay *= 2
    raise SystemExit(f"OSV query failed: {last_error}")


def write_summary(text):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)
        if not text.endswith("\n"):
            handle.write("\n")


def review(base_dir, head_dir):
    base = load_purls(base_dir)
    head = load_purls(head_dir)
    added = head - base
    if not added:
        message = "No new or upgraded dependencies in the release SBOMs.\n"
        print(message, end="")
        write_summary(message)
        return 0
    print(f"New or upgraded dependencies: {len(added)}")
    findings = query_osv(added)
    if not findings:
        message = "None of the new or upgraded dependencies have a moderate or higher known vulnerability.\n"
        print(message, end="")
        write_summary(message)
        return 0
    lines = ["New or upgraded dependencies with a moderate or higher known vulnerability:", ""]
    for purl in sorted(findings):
        rendered = ", ".join(f"{ident} ({label})" for ident, label in findings[purl])
        line = f"- `{purl}`: {rendered}"
        lines.append(line)
        print(f"::error::{purl}: {rendered}")
    text = "\n".join(lines)
    print(text)
    write_summary(text)
    return 1


def self_test():
    expected = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N": 3.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H": 10.0,
    }
    for vector, score in expected.items():
        actual = cvss_v3_base(vector)
        if actual != score:
            raise SystemExit(f"{vector}: expected {score}, got {actual}")
    moderate = advisory_rank({"database_specific": {"severity": "MODERATE"}, "severity": []})
    low = advisory_rank({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"}]})
    if moderate[1] < FAIL_FROM or low[1] >= FAIL_FROM:
        raise SystemExit(f"rank mismatch: {moderate} {low}")
    print("dependency-review self-test passed")


def main(argv):
    if argv == ["--self-test"]:
        self_test()
        return 0
    if len(argv) != 2:
        raise SystemExit("usage: dependency-review.py BASE_DIR HEAD_DIR")
    return review(argv[0], argv[1])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
