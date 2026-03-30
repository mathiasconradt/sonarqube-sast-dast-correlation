---
name: sonarqube-sast-dast-correlation
description: Correlate SAST findings from SonarQube with DAST findings from SARIF files (StackHawk, ZAP, etc.) and generate a comprehensive security report. Use when the user asks to correlate static and dynamic analysis results, cross-reference SonarQube with SARIF scan outputs, compare SonarQube and StackHawk/ZAP results, or generate a unified security findings report from .sarif files or SonarQube JSON exports.
trigger: |
  User wants to correlate SAST and DAST findings, generate a security correlation report,
  or compare static and dynamic analysis results
---

# SonarQube SAST-DAST Correlation

Generate a comprehensive security correlation report that maps SonarQube SAST findings with DAST findings from SARIF files.

## Workflow Overview

1. **Check for Existing Report** - Look for existing `sast-dast-correlation-report.md` and offer to open it or rerun analysis
2. **Gather Configuration** - Auto-detect SonarQube credentials from environment variables or config files
3. **Retrieve SAST Issues** - Fetch or reuse SonarQube issues, filtering out imported DAST issues
4. **Retrieve DAST Issues** - Select and parse SARIF files from DAST tools (StackHawk, ZAP, etc.)
5. **Deep Correlation Analysis** - Use AI Agent to match SAST and DAST findings with source code verification
6. **Validate Correlation Results** - Verify match quality before proceeding to report generation
7. **Generate Report** - Create comprehensive markdown report with severity analysis and recommendations
8. **Open in Browser** - Automatically open the report for review
9. **Tag Issues (Optional)** - Tag correlated issues in SonarQube for team tracking

**📖 For detailed workflow steps, see [Workflow Steps](references/workflow-steps.md)**

## Step 3: Fetch SonarQube Issues (SAST)

Use the SonarQube REST API to retrieve issues. Filter out imported DAST issues (e.g., `external_StackHawk:`):

```bash
# Fetch all issues for a project (replace values as needed)
curl -s -u "$SONAR_TOKEN:" \
  "https://sonarqube.example.com/api/issues/search?projectKeys=my-project&ps=500&p=1" \
  -o sonar_issues.json

# Filter out imported external issues
jq '[.issues[] | select(.rule | startswith("external_") | not)]' sonar_issues.json > sast_issues_filtered.json

# Verify issue count
jq 'length' sast_issues_filtered.json
```

## Step 4: Find and Parse SARIF Files (DAST)

Locate SARIF files using glob patterns, then validate structure before processing:

```bash
# Common SARIF output locations
find . -name "*.sarif" -o -name "*.sarif.json" 2>/dev/null

# Validate SARIF structure
jq '.runs[0].results | length' path/to/results.sarif

# Extract findings summary
jq '[.runs[0].results[] | {ruleId: .ruleId, uri: .locations[0].physicalLocation.artifactLocation.uri, message: .message.text}]' \
  path/to/results.sarif
```

## Step 5: Correlation Analysis

Use an Agent to perform intelligent correlation by matching SAST and DAST findings via source code analysis. Apply the following matching rules:

**Matching Logic (apply in order):**

1. **File/endpoint match** — Extract the file path from the SAST issue (`component` field) and the URL path from the DAST finding (`locations[0].physicalLocation.artifactLocation.uri`). Read the source file to map controller annotations (e.g., `@RequestMapping`, `@GetMapping`) to URL paths, then verify the DAST URL targets the same endpoint.

2. **Vulnerability category match** — Normalise rule IDs to categories before comparing. Examples of equivalent pairs: `squid:S3649` / `java:S3649` ↔ `sql-injection`; `squid:S5131` ↔ `xss`; `java:S2076` ↔ `command-injection`. Reject matches where categories differ.

3. **Confidence assignment** — Assign a confidence level based on how many criteria are satisfied:
   - **HIGH**: File/endpoint match confirmed AND vulnerability category match confirmed
   - **MEDIUM**: Vulnerability category match confirmed, endpoint match is probable but not fully verified
   - **LOW**: Same vulnerability category in the same application area, but endpoint mapping is ambiguous

```bash
# Example: build a candidate correlation list by joining on normalised category
jq -n \
  --slurpfile sast sast_issues_filtered.json \
  --slurpfile dast dast_findings.json \
  '[
    $sast[][] as $s |
    $dast[][] as $d |
    select($s.category == $d.category) |
    {sast_key: $s.key, dast_ruleId: $d.ruleId, file: $s.component, url: $d.uri, category: $s.category}
  ]' > candidate_correlations.json
```

After generating candidates, read the relevant source files to verify endpoint mappings and promote/demote confidence levels. Write the final result to `correlations.json`.

**📖 For complete correlation rules and validation logic, see [Correlation Analysis](references/correlation-analysis.md)**

## Step 6: Validate Correlation Results

Before generating the report, verify correlation quality:

```bash
# Check total correlation count
jq 'length' correlations.json

# Break down by confidence level
jq 'group_by(.confidence) | map({confidence: .[0].confidence, count: length})' correlations.json
```

- If zero correlations are found, **stop and inform the user** before proceeding. The most common cause is that SAST and DAST scanned different applications or found completely different vulnerability categories. Ask the user to confirm both tools targeted the same application.
- If only LOW-confidence correlations exist, surface this in the executive summary and recommend manual review.
- Only proceed to report generation once the correlation count and confidence distribution look reasonable.

## Report Generation

Using `correlations.json`, `sast_issues_filtered.json`, and the SARIF findings, write `sast-dast-correlation-report.md` with the following sections in order:

1. **Executive Summary** — total SAST issues, total DAST findings, total correlations, and overall risk posture
2. **Severity Distribution** — table breaking down findings by critical/high/medium/low across both tools
3. **Correlated Findings** — HIGH PRIORITY table of vulnerabilities confirmed by both tools, with file/line references and confidence level
4. **SAST-Only Findings** — code-level issues not detected at runtime, with remediation pointers
5. **DAST-Only Findings** — runtime issues invisible to static analysis, with remediation pointers
6. **Coverage Analysis** — identify complementary testing gaps (e.g., areas scanned by one tool but not the other)
7. **Actionable Recommendations** — prioritised fix list ordered by severity and confidence, with specific file/line references

**📖 For report template and structure, see [Report Template](references/report-template.md)**

## Error Handling

- If SonarQube API is unreachable, inform the user and offer to work with existing `sonar_issues.json`
- If no SARIF files are found, inform the user and ask for a file path
- Validate SARIF file format with `jq .runs[0].results` before processing; if invalid, prompt the user to verify the file
- Remember to filter out `external_StackHawk:` or similar imported issues from SAST data
- If correlation produces zero matches, verify that SAST and DAST scanned the same application (the most common reason is they scanned different apps or found completely different vulnerability categories)

## Output Files

- `sonar_issues.json` - SAST issues from SonarQube (if created)
- `correlations.json` - Correlation analysis results from Agent (intermediate file)
- `sast-dast-correlation-report.md` - Final correlation report with detailed findings

## Additional Resources

**Detailed Documentation:**
- [Workflow Steps](references/workflow-steps.md) - Detailed steps for gathering config, retrieving SAST/DAST issues
- [Correlation Analysis](references/correlation-analysis.md) - Complete correlation rules, validation logic, and source code analysis workflow
- [Report Template](references/report-template.md) - Full markdown report structure and formatting
- [Implementation Guide](references/implementation-guide.md) - Step-by-step implementation workflow and key success factors

**Examples and Reference:**
- [Examples Overview](references/examples/README.md) - Collection of example correlation reports
  - [SonarQube + ZAP Example](references/examples/sonarqube-zap-example/README.md) - Java Spring Boot application example
  - [SonarQube + StackHawk Example](references/examples/sonarqube-stackhawk-example/README.md) - Java Spring Boot application example
