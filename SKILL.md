---
name: sonarqube-sast-dast-correlation
description: Correlate SAST findings from SonarQube with DAST findings from SARIF files (StackHawk, ZAP, etc.) and generate a comprehensive security report. Use when the user asks to correlate static and dynamic analysis results, cross-reference SonarQube with SARIF scan outputs, compare SonarQube and StackHawk/ZAP results, or generate a unified security findings report from .sarif files or SonarQube JSON exports.
---

# SonarQube SAST-DAST Correlation

Generate a comprehensive security correlation report that maps SonarQube SAST findings with DAST findings from SARIF files. All files are stored in `.sonar/` subdirectory.

**Workflow:** Check existing report → Gather config (Steps 1-2 in [Workflow Steps](references/workflow-steps.md)) → Execute Steps 3-6 below → Generate report → Tag issues (optional)

## ⚠️ CRITICAL: Correlation and Tagging

**TRUE correlation:** Valid SonarQube issue key (not "N/A"), matching DAST finding, matching category and endpoint. DAST-only findings (no SAST key) go in report Section 5, not tagged.

**Tagging workflow (tag: `dast-detected`):**
1. Delete old comments: `GET /api/issues/search?tags=dast-detected&additionalFields=comments`, then `DELETE /api/issues/delete_comment` for all comments containing 🔴/🟠/🟡/🔵 or "DAST Correlation"
2. Clear old tags: `POST /api/issues/remove_tags?tags=dast-detected`
3. Apply fresh tags: `POST /api/issues/set_tags?issue={key}&tags=dast-detected` then `POST /api/issues/add_comment` with `{icon} **DAST Correlation - {CONFIDENCE}**`

**📖 [Implementation Guide - Step 10](references/implementation-guide.md) for complete API examples**

## Step 3: Fetch SonarQube Issues (SAST)

Fetch issues via SonarQube REST API, filter out imported DAST issues:

```bash
mkdir -p .sonar
curl -s -u "$SONAR_TOKEN:" \
  "https://sonarqube.example.com/api/issues/search?projectKeys=my-project&ps=500&p=1" \
  -o .sonar/sonar_issues.json
jq '[.issues[] | select(.rule | startswith("external_") | not)]' .sonar/sonar_issues.json > .sonar/sast_issues_filtered.json
jq 'length' .sonar/sast_issues_filtered.json
```

## Step 4: Find and Parse SARIF Files (DAST)

Locate and validate SARIF files:

```bash
find . -name "*.sarif" -o -name "*.sarif.json" 2>/dev/null
jq '.runs[0].results | length' path/to/results.sarif
jq '[.runs[0].results[] | {ruleId: .ruleId, uri: .locations[0].physicalLocation.artifactLocation.uri, message: .message.text}]' \
  path/to/results.sarif
```

## Step 5: Correlation Analysis

Match SAST and DAST findings via source code analysis on file/endpoint, vulnerability category, and confidence level. Write to `.sonar/correlations.json` with valid SAST issue keys only.

```bash
jq -n \
  --slurpfile sast .sonar/sast_issues_filtered.json \
  --slurpfile dast .sonar/dast_findings.json \
  '[
    $sast[][] as $s |
    $dast[][] as $d |
    select($s.category == $d.category) |
    {sast_key: $s.key, dast_ruleId: $d.ruleId, file: $s.component, url: $d.uri, category: $s.category}
  ]' > .sonar/candidate_correlations.json
```

**📖 [Correlation Analysis](references/correlation-analysis.md) for complete rules**

## Step 6: Validate Correlation Results

```bash
jq 'length' .sonar/correlations.json
jq 'group_by(.confidence) | map({confidence: .[0].confidence, count: length})' .sonar/correlations.json
```

Zero correlations: **Stop.** Confirm tools scanned same app. LOW confidence only: note in summary, recommend manual review.

## Report Generation

Write `.sonar/sast-dast-correlation-report.md` with sections: Executive Summary, Severity Distribution, Correlated Findings (HIGH PRIORITY), SAST-Only Findings, DAST-Only Findings, Coverage Analysis, Actionable Recommendations.

**📖 See [Report Template](references/report-template.md) for structure**

## Error Handling

API unreachable: use existing `.sonar/sonar_issues.json`. No SARIF: ask for path. Invalid SARIF: validate with `jq .runs[0].results`. Filter `external_*` imports. Zero correlations: confirm same app scanned.

## Output Files

All in `.sonar/` subdirectory: `sonar_issues.json`, `sast_issues_filtered.json`, `correlations.json`, `sast-dast-correlation-report.md`. Add `.sonar/` to `.gitignore`.

## Additional Resources

- [Workflow Steps](references/workflow-steps.md)
- [Correlation Analysis](references/correlation-analysis.md)
- [Report Template](references/report-template.md)
- [Implementation Guide](references/implementation-guide.md)
