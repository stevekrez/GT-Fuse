#!/usr/bin/env python3
"""
fuse.py
- Reads Trivy JSONs and Grype JSONs to create one Excel file with a tab for each combined image.
"""
import argparse
import glob
import json
import os
import re
import urllib.request
from typing import Iterable, List, Dict
import numpy as np
import pandas as pd
from collections import defaultdict

# Columns for XLSX
EXPECTED_COLUMNS = [
    "Package",
    "Type",
    "CVEs",
    "Installed Versions",
    "Fixed Versions",
    "Severity",
]

# Map Trivy Results[].Type to Grype
TRIVY_TYPE_MAP = {
    # Operating system packages
    "debian": "deb",
    "ubuntu": "deb",
    "alpine": "apk",
    "redhat": "rpm",
    "rhel": "rpm",
    "centos": "rpm",
    "oracle": "rpm",
    "rocky": "rpm",
    "alma": "rpm",
    "suse": "rpm",
    "amazon": "rpm",
    # languages and dependenices
    "jar": "java-archive",
    "java-archive": "java-archive",
    "maven": "java-archive",
    "npm": "node",
    "nodejs": "node",
    "yarn": "node",
    "golang": "golang",
    "go-module": "golang",
    "gobinary": "golang",
    "go": "golang",
    "python": "python",
    "pip": "python",
    "gem": "gem",
    "ruby": "ruby",
}

# Excel column widths
EXCEL_COLUMN_WIDTHS = {
    "Package": 26,
    "Type": 10.5,
    "CVEs": 22,
    "Installed Versions": 24,
    "Fixed Versions": 24,
    "Severity": 10.5,
    "KEV": 6.5
}

# Advisory regexes
DASH = r"[-\u2010-\u2015]"

REGEX_GHSA = re.compile(rf"\bGHSA-[A-Za-z0-9]{{4}}-[A-Za-z0-9]{{4}}-[A-Za-z0-9]{{4}}\b", re.I)
REGEX_RHSA = re.compile(rf"\bRHSA-[0-9]{{4}}:[0-9]{{4,6}}\b", re.I)
REGEX_ALAS = re.compile(rf"\bALAS(?:2)?{DASH}?[0-9]{{4}}{DASH}[0-9]{{3,5}}\b", re.I)
REGEX_ELSA = re.compile(rf"\bELSA{DASH}[0-9]{{4}}{DASH}[0-9]{{4,6}}\b", re.I)
REGEX_USN  = re.compile(rf"\bUSN{DASH}[0-9]{{1,5}}{DASH}[0-9]{{1,2}}\b", re.I)
REGEX_CVE = re.compile(rf"\bCVE{DASH}[0-9]{{4}}{DASH}[0-9]{{4,8}}\b", re.I)
REGEX_SUSE_SU = re.compile(rf"\b(?:SUSE|openSUSE)-SU{DASH}[0-9]{{4}}:[0-9]{{4,6}}\b", re.I)

# KEV Catalog
KEV_CISA_GITHUB = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

# Go Types
GO_TYPES = {"go-module", "gobinary", "go", "golang"}

# Get name for sheet from Grype output file
def extract_grype_sheet_name(json_path: str):
    try:
        with open(json_path, "r", encoding="utf-8") as file:
            data = json.load(file)
        tags = (((data or {}).get("source", {}) or {}).get("target", {}) or {}).get("tags", [])
        if isinstance(tags, list):
            try:
                return str(tags[0])
            except IndexError:
                return None
    except Exception:
        pass
    return ""

# Get Grype image ID
def extract_grype_image_id(json_path: str):
    try:
        with open(json_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            grype_id = str((((data or {}).get("source", {}) or {}).get("target", {}) or {}).get("imageID", "") or "").strip()
        return grype_id
    except Exception:
        return ""

# Get name for sheet from Trivy output file
def extract_trivy_sheet_name(json_path: str):
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        artifact_name = data.get("ArtifactName") or ""
        if isinstance(artifact_name, str) and artifact_name.strip():
            return artifact_name.strip()
        for result in data.get("Results", []) or []:
            target = (result or {}).get("Target", "")
            if isinstance(target, str) and target.strip():
                return target.strip()
    except Exception:
        pass
    return os.path.basename(json_path)

# Get Trivy image ID
def extract_trivy_image_id(json_path: str):
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            trivy_id = str((((data or {}).get("Metadata", {}) or {}).get("ImageID", "") or "")).strip()
        return trivy_id
    except Exception:
        return ""

# Normalize CVEs
def normalize_cves(series: pd.Series):
    cve_string = series.fillna("").astype(str)
    cve_string = cve_string.str.replace("\r\n", "\n").str.replace("\r", "\n")
    cve_string = cve_string.str.replace(r"\\n", "\n", regex=True)
    return cve_string

# Aggregation functions
# Convert ID to uppercase for comparisons
def convert_id(id: str):
    id = id.strip()
    if not id:
        return ""
    return id.upper()

# Get CVE
def cve_token(id: str):
    cve = REGEX_CVE.search(id)
    if cve:
        cve = cve.group(0).upper()
    else:
        cve = ""
    return cve

# Extract unique CVEs
def extract_cves(cell: str):
    out = []
    for part in re.split(r"[\s,]+", cell.strip()) if cell else []:
        marked = REGEX_CVE.search(part)
        if marked:
            extracted = marked.group(0).upper()
            if extracted not in out:
                out.append(extracted)
    for marked in REGEX_CVE.finditer(cell):
        extracted = marked.group(0).upper()
        if extracted not in out:
            out.append(extracted)
    return out

# Split cell value into unique parts
def split_values(cell: str):
    if cell is None:
        return []
    parts = re.split(r"[,\n]+", str(cell))
    unique_parts = []
    seen_values = set()
    for element in parts:
        cleaned = element.strip()
        if not cleaned:
            continue
        if cleaned not in seen_values:
            seen_values.add(cleaned)
            unique_parts.append(cleaned)
    return unique_parts

# De-duplicate IDs and ensure each CVE appears once
def deduplicate_ids(ids: List[str]):
    seen_ids = set()
    seen_cves = set()
    out = []
    for raw in ids:
        string = (raw or "").strip()
        if not string:
            continue
        original = convert_id(string)
        cve = cve_token(original)
        if original in seen_ids:
            continue
        if cve and cve in seen_cves:
            continue
        out.append(original)
        seen_ids.add(original)
        if cve:
            seen_cves.add(cve)
    return out

# Dreate mapping for severity ranks
SEVERITY_RANK = {
    "CRITICAL": 5, "Critical": 5,
    "HIGH": 4, "High": 4,
    "MEDIUM": 3, "Medium": 3,
    "LOW": 2, "Low": 2,
    "UNKNOWN": 1, "Unknown": 1, "": 1,
}

# Create mapping of original severity rankings
ORIGINAL_RANK = {5: "Critical",
    4: "High",
    3: "Medium",
    2: "Low",
    1: "Unknown"
}

# Aggregate severities from finding into highest severity rank
def aggregate_severity(severity_values: List[str]):
    highest_rank = 1
    for severity in severity_values:
        core = str(severity or "")
        highest_rank = max(highest_rank, SEVERITY_RANK.get(core, SEVERITY_RANK.get(core.title(), 1)))
    label = ORIGINAL_RANK.get(highest_rank, "Unknown")
    return label

# Combine packages for de-duplication purposes
def combine_by_package(df: pd.DataFrame):
    # Ensure expected columns exist
    for col in EXPECTED_COLUMNS:
        if col not in df.columns:
            df[col] = ""

    # Check if dataframe is empty first to prevent errors where no packages are present
    if df.empty:
        return df

    df = df.copy()
    df["Type"] = df["Type"].map(normalize_type)

    grouped_package_type = df.groupby(["Package", "Type"], dropna=False, sort=False)
    new_rows = []

    for (package, typ), grouped in grouped_package_type:
        # Gather CVEs
        ids_all = []
        for cell in grouped["CVEs"].tolist():
            ids_all.extend(split_values(cell))
        ids_all = order_cves_first(deduplicate_ids(ids_all))

        # Gather Installed versions
        installed_cells = grouped["Installed Versions"].tolist()
        installed_flat = []
        for cell in installed_cells:
            installed_flat.extend(split_values(cell))
        installed_all = dedupe_and_order(installed_flat)

        # Gather Fixed versions
        fixed_cells = grouped["Fixed Versions"].tolist()
        fixed_flat = []
        for cell in fixed_cells:
            fixed_flat.extend(split_values(cell))
        fixed_all = get_latest_version(fixed_flat)

        # Aggregate severity
        severity_cells = grouped["Severity"].tolist()
        agg_sev = aggregate_severity(severity_cells)

        # Create row with gathered values
        new_rows.append([
            package,
            typ,
            "\n".join(ids_all),
            "\n".join(installed_all),
            "\n".join(fixed_all),
            agg_sev,
        ])

    out = pd.DataFrame(new_rows, columns=EXPECTED_COLUMNS)
    out["CVEs"] = normalize_cves(out["CVEs"])
    return out

# Remove duplicates and keep original order
def dedupe_and_order(items: List[str]):
    seen = set()
    out = []
    for finding in items:
        normalized = re.sub(r"^\d+:", "", finding.strip())
        if normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out

# Convert version string into a key to only output the hightest / most recent version
def version_key(s: str):
    s = (s or "").strip()
    parts = re.split(r"(\d+)", s)
    key = []
    for part in parts:
        if not part:
            continue
        if part.isdigit():
            key.append(int(part))
        else:
            key.append(part)
    return tuple(key)

# Return latest / most recent fixed version of a package
def get_latest_version(items: List[str]):
    deduped = dedupe_and_order(items)
    if not deduped:
        return []
    latest = max(deduped, key=version_key)
    return [latest]

def normalize_type(t: str) -> str:
    t = (t or "").strip().lower()
    return "golang" if t in GO_TYPES else t

# Trivy JSON input
# Get Trivy type
def map_trivy_type(type: str):
    if not type:
        return ""
    type_low = str(type).strip().lower()
    mapped_type = TRIVY_TYPE_MAP.get(type_low, type_low)
    # normalize go flavors (gobinary, go-module, etc.) to a single "golang"
    return normalize_type(mapped_type)

# Get Trivy advisory IDs
def collect_advisory_ids_from_trivy(vuln: Dict):
    ids = []
    vuln_id = str(vuln.get("VulnerabilityID", "") or "")
    if vuln_id:
        ids.append(convert_id(vuln_id))

    refs = vuln.get("References", []) or []
    prim = vuln.get("PrimaryURL", "")
    if prim:
        refs.append(prim)

    for reference in refs:
        string_reference = str(reference or "")
        for regex_test in (REGEX_GHSA, REGEX_RHSA, REGEX_ALAS, REGEX_ELSA, REGEX_USN, REGEX_CVE):
            for m in regex_test.finditer(string_reference):
                val = convert_id(m.group(0))
                if val not in ids:
                    ids.append(val)
    return ids

###
# Read Trivy JSON output
def read_trivy_json(json_path: str):
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"Failed to read {json_path}: {e}")
        trivy_read_error = pd.DataFrame(columns=EXPECTED_COLUMNS)
        return trivy_read_error

    results = data.get("Results", []) or []
    rows: List[List[str]] = []

    for result in results:
        reported_type = map_trivy_type((result or {}).get("Type", "") or "")
        vulns_list = (result or {}).get("Vulnerabilities", []) or []
        for vulnerability in vulns_list:
            package = str(vulnerability.get("PkgName", "") or vulnerability.get("PkgID", "") or "")
            installed = str(vulnerability.get("InstalledVersion", "") or "")
            fixed = str(vulnerability.get("FixedVersion", "") or "")
            severity = str(vulnerability.get("Severity", "") or "Unknown")

            ids = collect_advisory_ids_from_trivy(vulnerability)
            cves_cell = "\n".join(ids)

            rows.append([package, reported_type, cves_cell, installed, fixed, severity])

    df = pd.DataFrame(rows, columns=EXPECTED_COLUMNS)
    df = df.replace([np.inf, -np.inf], pd.NA).fillna("")
    return df

# Grype JSON input
# Get all JSON files from Grype folder
def iter_paths(spec: Iterable[str]):
    for string in spec:
        if os.path.isdir(string):
            for file in glob.glob(os.path.join(string, "**", "*.json"), recursive=True):
                yield file
        else:
            for file in glob.glob(string):
                if os.path.isfile(file):
                    yield file

# Parse Grype JSON outputs
def parse_grype_json_one(json_path: str):
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        print(f"Failed to read {json_path}: {e}")
        grype_read_error = pd.DataFrame(columns=EXPECTED_COLUMNS)
        return grype_read_error

    found_matches = data.get("matches", [])
    rows: List[List[str]] = []

    for match in found_matches:
        vuln = match.get("vulnerability", {}) or {}
        art = match.get("artifact", {}) or {}

        package = str(art.get("name", "") or "")
        installed = str(art.get("version", "") or "")
        type_raw = str(art.get("type", "") or "")
        type = normalize_type(type_raw)
        #type = str(art.get("type", "") or "")

        id_list = []
        vulnerability_id = str(vuln.get("id", "") or "")
        if vulnerability_id:
            id_list.append(convert_id(vulnerability_id))

        advisories = vuln.get("advisories", []) or []
        if isinstance(advisories, list):
            for advisory in advisories:
                advisory_id = str((advisory or {}).get("id", "") or "")
                if advisory_id:
                    id_list.append(convert_id(advisory_id))

        related_vulnerabilities = vuln.get("relatedVulnerabilities", []) or []
        if isinstance(related_vulnerabilities, list):
            for related_vuln in related_vulnerabilities:
                related_vuln_id = str((related_vuln or {}).get("id", "") or "")
                if related_vuln_id:
                    id_list.append(convert_id(related_vuln_id))

        # dedup preserving order
        seen = set(); ids_unique = []
        for item in id_list:
            if item not in seen:
                seen.add(item); ids_unique.append(item)
        cves_cell = "\n".join(ids_unique)

        fix = vuln.get("fix", {}) or {}
        fixed_versions = fix.get("versions", []) or []
        fixed = ", ".join(map(str, fixed_versions)) if fixed_versions else ""
        severity = str(vuln.get("severity", "") or "") or "Unknown"

        # KEV values in Grype ouput
        kev = vuln.get("knownExploited")
        true_table = {"true", "yes", "y", "1"}
        kev_bool = False

        if isinstance(kev, bool):
            kev_bool = kev
        elif isinstance(kev, (int, float)):
            kev_bool = kev != 0
        elif isinstance(kev, str):
            kev_bool = kev.strip().lower() in true_table
        elif isinstance(kev, dict):
            kev_bool = bool(str(kev.get("cve", "")).strip())
        elif isinstance(kev, (list, tuple)):
            for entry in kev:
                if isinstance(entry, bool) and entry:
                    kev_bool = True; break
                if isinstance(entry, (int, float)) and entry != 0:
                    kev_bool = True; break
                if isinstance(entry, str) and entry.strip().lower() in true_table:
                    kev_bool = True; break
                if isinstance(entry, dict) and str(entry.get("cve", "")).strip():
                    kev_bool = True; break

        if kev_bool and "(KEV)" not in severity:
            severity = f"{severity} (KEV)" if severity else "Unknown (KEV)"

        rows.append([package, type, cves_cell, installed, fixed, severity])

    df = pd.DataFrame(rows, columns=EXPECTED_COLUMNS)
    df = df.replace([np.inf, -np.inf], pd.NA).fillna("")
    return df

# KEV support for Trivy input
def load_kev_ids_from_github(url: str = KEV_CISA_GITHUB, timeout: int = 20):
    kev = set()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = resp.read()
        try:
            data = json.loads(body)
        except Exception:
            data = None
        if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
            for it in data["vulnerabilities"]:
                cid = (it or {}).get("cveID") or (it or {}).get("cve_id") or (it or {}).get("cve")
                if cid:
                    for c in extract_cves(str(cid)):
                        kev.add(c)
        elif isinstance(data, list):
            for it in data:
                cid = (it or {}).get("cveID") or (it or {}).get("cve_id") or (it or {}).get("cve")
                if cid:
                    for c in extract_cves(str(cid)):
                        kev.add(c)
        if not kev:
            text = body.decode("utf-8", errors="ignore")
            for c in extract_cves(text):
                kev.add(c)

    except Exception as e:
        print(f"Could not fetch KEV from GitHub at ({url}): {e}")

    return kev

# Mark CVE with KEV if applicable
def mark_kev_cve(cell: str, kev_ids: set):
    if not kev_ids or not cell:
        return cell or ""
    parts = split_values(cell)
    out = []
    for p in parts:
        cv = cve_token(p)
        if cv and cv in kev_ids and "(KEV)" not in p:
            out.append(f"{p} (KEV)")
        else:
            out.append(p)
    return "\n".join(order_cves_first(out))

# Return "Yes" if a CVE is a KEV
def kev_flag_for_cell(cell: str, kev_ids: set):
    if not cell or not kev_ids:
        return "No"
    return "Yes" if any(c in kev_ids for c in extract_cves(cell)) else "No"

# Apply to CVE column of dataframe
def mark_df_kev_cve(df: pd.DataFrame, kev_ids: set):
    if df.empty or "CVEs" not in df.columns or not kev_ids:
        return df
    df = df.copy()
    df["CVEs"] = df["CVEs"].map(lambda x: mark_kev_cve(x, kev_ids))
    return df

# Add KEV column when --kev flag is present
def add_kev_flag_column(df: pd.DataFrame, kev_ids: set, insert_after: str = "Severity"):
    df = df.copy()
    if df.empty:
        df["KEV"] = "No"
        return df
    flags = [kev_flag_for_cell(val, kev_ids) for val in df["CVEs"].astype(str)]
    if insert_after in df.columns:
        pos = list(df.columns).index(insert_after) + 1
        df.insert(pos, "KEV", flags)
    else:
        df["KEV"] = flags
    return df

# Order CVEs first, then advisories alphabetically
def order_cves_first(ids: List[str]):
    cves = []
    advisories = []
    for s in ids:
        if cve_token(s):
            cves.append(s)
        else:
            advisories.append(s)
    advisories_sorted = sorted(advisories, key=lambda x: x.upper())
    return cves + advisories_sorted

# Create sheet name
def create_sheet_name(name: str):
    base = os.path.basename(name or "")
    base = re.sub(r"\.json$", "", base)
    base = re.sub(r"\.tar(\.gz)?$", "", base)
    base = base.replace(":", "_")
    return base.strip() or "Combined"

# Trivy specific sheet id and name
def sheet_key_and_name_from_trivy(path: str):
    img_id = extract_trivy_image_id(path)
    display = extract_trivy_sheet_name(path) or os.path.basename(path)
    return (img_id or create_sheet_name(display), create_sheet_name(display))

# Grype specific sheet id and name
def sheet_key_and_name_from_grype(path: str):
    img_id = extract_grype_image_id(path)
    display = extract_grype_sheet_name(path) or os.path.basename(path)
    return (img_id or create_sheet_name(display), create_sheet_name(display))

# Excel writer
def excel_sheet_name(name: str):
    name = re.sub(r"[:\\/?*\[\]]", "_", str(name or ""))
    return name[:31]

def unique_sheet_name(raw: str, seen: Dict[str, int]):
    base = excel_sheet_name(raw)
    name = base
    i = seen.get(base, 0)
    while name in seen:
        i += 1
        suffix = f"_{i}"
        name = (base[:31 - len(suffix)] + suffix)
    seen[name] = 1
    return name

def pick_sheet_name(trivy_files: List[str], grype_files: List[str]):
    # Prefer Trivy ArtifactName (Results[].Target)
    for p in trivy_files:
        n = extract_trivy_sheet_name(p)
        if n:
            return excel_sheet_name(n)

    # Prefer Grype image tag
    for p in grype_files:
        n = extract_grype_sheet_name(p)
        if n:
            return excel_sheet_name(n)

    # Last resort to choose first filename
    all_files = trivy_files + grype_files
    if all_files:
        base = os.path.splitext(os.path.basename(all_files[0]))[0]
        return excel_sheet_name(base)

    return "Combined"

def write_df_to_sheet(writer: pd.ExcelWriter, df: pd.DataFrame, sheet_name: str):
    df.to_excel(writer, sheet_name=sheet_name, index=False)

    workbook = writer.book
    ws = writer.sheets[sheet_name]

    bordered = workbook.add_format({"border": 1, "text_wrap": True})
    header_fmt = workbook.add_format({"border": 1, "bold": True, "text_wrap": True})

    for item, column in enumerate(df.columns.tolist()):
        ws.set_column(item, item, EXCEL_COLUMN_WIDTHS.get(column, 16))

    for column_number, value in enumerate(df.columns.tolist()):
        ws.write(0, column_number, value, header_fmt)

    number_rows, number_columns = df.shape
    for row in range(number_rows):
        for column in range(number_columns):
            ws.write(row + 1, column, df.iat[row, column], bordered)

    ws.autofilter(0, 0, max(number_rows, 1), max(number_columns - 1, 0))

def main():
    ap = argparse.ArgumentParser(description="Combine Trivy JSON and Grype JSON into a single .xlsx file")
    ap.add_argument("--trivy", nargs="*", default=[],
                    help="Directory or file for Trivy JSON file(s) (e.g., /path/to/*.json)")
    ap.add_argument("--grype", nargs="*", default=[],
                    help="Directory or file for Grype JSON file(s) (e.g., /path/to/*.json)")
    ap.add_argument("--kev", action="store_true", help="Check KEV from CISA GitHub and tag Trivy rows if a CVE is present.")

    out_group = ap.add_mutually_exclusive_group(required=True)
    out_group.add_argument("--out", help="Output .xlsx path (multi-sheet, one sheet per image)")
    out_group.add_argument("--csv", help="Output .csv path (single combined CSV)")


    args = ap.parse_args()

    kev_ids = set()
    if args.kev:
        github_kev = load_kev_ids_from_github(KEV_CISA_GITHUB)
        # Check if KEVs are available
        if github_kev:
            print(f"Loaded {len(github_kev)} KEV CVE IDs from GitHub")
            kev_ids |= github_kev
        else:
            print("No KEV CVE IDs loaded from GitHub")

    if kev_ids:
        print(f"Total KEV CVE IDs in use: {len(kev_ids)}")


    # Resolve file lists - fixed issue where it duplicated
    trivy_json_files = []
    for spec in args.trivy or []:
        if os.path.isdir(spec):
            trivy_json_files.extend(glob.glob(os.path.join(spec, "**", "*.json"), recursive=True))
        else:
            trivy_json_files.extend(glob.glob(spec))

    trivy_json_files = list(dict.fromkeys([f for f in trivy_json_files if os.path.isfile(f)]))
    grype_files = list(dict.fromkeys([p for p in iter_paths(args.grype) if os.path.isfile(p)]))

    # Create CSV file
    if args.csv:
        combined_frames = []
        frames_by_id: Dict[str, list] = {}
        name_by_id: Dict[str, str] = {}
        # Trivy
        for trivy_file in trivy_json_files:
            try:
                if os.path.getsize(trivy_file) == 0:
                    print(f"Skipping empty file: {trivy_file}")
                    continue
                df = read_trivy_json(trivy_file)
                if df.empty:
                    print(f"No vulnerabilities found in Trivy output: {trivy_file}")
                    continue
                key, sheet_name = sheet_key_and_name_from_trivy(trivy_file)
                frames_by_id.setdefault(key, []).append(df)
                if key not in name_by_id:
                    name_by_id[key] = extract_trivy_sheet_name(trivy_file) or sheet_name
            except Exception as e:
                print(f"Failed to process Trivy JSON {trivy_file}: {e}")

        # Grype
        for grype_file in grype_files:
            try:
                if os.path.getsize(grype_file) == 0:
                    print(f"Skipping empty file: {grype_file}")
                    continue
                df = parse_grype_json_one(grype_file)
                if df.empty:
                    print(f"No vulnerabilities found in Grype output: {grype_file}")
                    continue
                key, nice_name = sheet_key_and_name_from_grype(grype_file)
                frames_by_id.setdefault(key, []).append(df)
                # prefer tag from Grype in case only Grype is supplied
                tag = extract_grype_sheet_name(grype_file)
                if tag:
                    name_by_id[key] = tag
                elif key not in name_by_id:
                    name_by_id[key] = sheet_name
            except Exception as e:
                print(f"Failed to process Grype JSON {grype_file}: {e}")

        combined_frames = []
        for key, parts in frames_by_id.items():
            try:
                merged = pd.concat(parts, ignore_index=True)
                merged = combine_by_package(merged)
                merged = mark_df_kev_cve(merged, kev_ids)
                if args.kev:
                    merged = add_kev_flag_column(merged, kev_ids)

                image_display = name_by_id.get(key)
                merged = merged.copy()
                merged.insert(0, "Image", image_display)
                combined_frames.append(merged)
            except Exception as e:
                print(f"Failed to finalize image group {key}: {e}")

        if combined_frames:
            out_df = pd.concat(combined_frames, ignore_index=True)
            try:
                out_df.to_csv(args.csv, index=False)
                print(f"CSV file saved: {args.csv}")
            except Exception as e:
                print(f"Failed to save CSV to {args.csv}: {e}")
        else:
            print("No valid data found. Skipping CSV file creation.")
        return

    # Create XLSX writer to write to sheets
    writer = pd.ExcelWriter(args.out, engine="xlsxwriter")
    wrote_any = False
    seen_sheet_names: Dict[str, int] = {}

    # Create frames for image IDs
    frames_by_id: Dict[str, list] = {}
    name_by_id: Dict[str, str] = {}

    # Write Trivy to sheet
    for trivy_file in trivy_json_files:
        try:
            if os.path.getsize(trivy_file) == 0:
                print(f"Skipping empty file: {trivy_file}")
                continue
            df = read_trivy_json(trivy_file)
            if df.empty:
                print(f"No vulnerabilities found in Trivy output: {trivy_file}")
                continue

            key, sheet_name = sheet_key_and_name_from_trivy(trivy_file)
            frames_by_id.setdefault(key, []).append(df)
            name_by_id.setdefault(key, sheet_name)
        except Exception as e:
            print(f"Failed to process Trivy JSON {trivy_file}: {e}")

    # Write Grype to sheet
    for grype_file in grype_files:
        try:
            if os.path.getsize(grype_file) == 0:
                print(f"Skipping empty file: {grype_file}")
                continue
            df = parse_grype_json_one(grype_file)
            if df.empty:
                print(f"No vulnerabilities found in Grype output: {grype_file}")
                continue

            key, sheet_name = sheet_key_and_name_from_grype(grype_file)
            frames_by_id.setdefault(key, []).append(df)
            name_by_id.setdefault(key, sheet_name)
        except Exception as e:
            print(f"Failed to process Grype JSON {grype_file}: {e}")

    # Merge for combined sheet
    for key, parts in frames_by_id.items():
        try:
            merged = pd.concat(parts, ignore_index=True)
            merged = combine_by_package(merged)
            merged = mark_df_kev_cve(merged, kev_ids)
            if args.kev:
                merged = add_kev_flag_column(merged, kev_ids)

            sheet = unique_sheet_name(name_by_id.get(key, "Combined"), seen_sheet_names)
            write_df_to_sheet(writer, merged, sheet)
            wrote_any = True
        except Exception as e:
            print(f"Failed to write sheet for key {key}: {e}")

    # Ensure data is written and saved
    writer.close()
    if wrote_any:
        print(f"Excel file saved: {args.out}")
    else:
        try:
            if os.path.exists(args.out):
                os.remove(args.out)
        except Exception:
            pass
        print("No valid data found. Skipping Excel file creation.")

if __name__ == "__main__":
    main()
