# GT-Fuse: Grype Trivy Hybrid Script

fuse.py is a script for combining vulnerability scan results from Trivy and Grype into a single, human-readable report.  
The outputs include Excel (.xlsx) (one sheet per image) or a single CSV (flat table).  
It optionally tags Known Exploited Vulnerabilities (KEV) using CISA’s public list.

## Features
- **Merge sources:** Reads Trivy and Grype JSON and merges findings for each image.
- **XLSX or CSV:** One sheet per image (XLSX) or a single flat CSV.
- **De-duplication:** Groups by `Package`+`Type`, dedupes IDs (CVEs + advisories), merges versions, keeps **highest** severity.
- **Advisory extraction:** Detects `CVE-*`, **GHSA**, **RHSA**, **ALAS**, **ELSA**, **USN** from references.
- **KEV tagging:** `--kev` tags CVEs found in CISA KEV and adds a `KEV` Yes/No column.
- **Type normalization:** Maps Trivy types (e.g., `debian`, `maven`, `npm`) to Grype-style (`deb`, `java-archive`, `node`, etc.).
- **Error handling:** Skips empty/malformed files, tolerates missing fields, avoids duplicate inputs.


## Requirements
**Python**: 3.9+ recommended

**Packages**:
  ```bash
  pip install pandas numpy xlsxwriter
  ```

or install required modules via requirements.txt:
  ```bash
  pip install -r requirements.txt
  ```

**Virtual Environment**:
  ```bash
  python -m venv venv
  venv/bin/pip install numpy pandas xlsxwriter
  source venv/bin/activate
  python3 fuse.py
  ```

## Trivy Commands:
**Docker Repository**:
  ```bash
  for img in $(docker images --format ‘{{.Repository}}; do trivy image --ignore-unfixed --format json -o "trivy/trivy-${.Respository}.json“
  ```

**Saved .tar images**:
  ```bash
  for file in *.tar; do trivy image --ignore-unfixed --format json --input "$file" > "${file%.tar}".json; done
  ```

## Grype Commands:
**Docker Repository**:
  ```bash
  for img in $(docker images --format ‘{{.Repository}}; do grype --only-fixed -o json > "grype/grype-${.Respository}.json"
  ```

**Saved .tar images**:
  ```bash
  for file in *.tar; do grype --only-fixed -o json "$file" > "${file%.tar}".json; done
  ```

## fuse.py Usage
**Excel Output**:
  ```bash
  python3 fuse.py --trivy trivy/ --grype grype/ --kev --out ./fused_output.xlsx
  ```

**CSV Output**:
  ```bash
  python3 fuse.py --trivy trivy/ --grype grype/ --kev --csv ./fused_output.csv
  ```
