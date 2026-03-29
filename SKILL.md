---
name: sonarqube-sast-dast-correlation
description: Correlate SAST findings from SonarQube with DAST findings from SARIF files (StackHawk, ZAP, etc.) and generate a comprehensive security report
trigger: |
  User wants to correlate SAST and DAST findings, generate a security correlation report,
  or compare static and dynamic analysis results
---

# SonarQube SAST-DAST Correlation

Generate a comprehensive security correlation report that maps Static Application Security Testing (SAST) findings from SonarQube with Dynamic Application Security Testing (DAST) findings from SARIF files.

## Workflow

### 0. Check for Existing Report

Before starting the analysis, check if `sast-dast-correlation-report.md` already exists in the current directory.

If it exists:
1. Use AskUserQuestion to ask the user:
   - **Option 1:** "Open existing report" - Just open the existing report in the browser and skip to step 7
   - **Option 2:** "Rerun analysis" - Delete the existing report and proceed with fresh analysis from step 1

If it doesn't exist, proceed to step 1.

### 1. Gather SonarQube Configuration

**IMPORTANT:** Automatically check environment variables FIRST using Bash before reading config files.

Check for SonarQube configuration in the following order:

1. **Environment variables** (check these FIRST with `env | grep -i sonar`):
   - `SONARQUBE_URL` or `SONAR_HOST_URL` (for SonarQube URL)
   - `SONARQUBE_TOKEN` or `SONAR_TOKEN` (for authentication token)
   - `SONAR_PROJECT_KEY` or `SONARQUBE_PROJECT_KEY` (for project key)

2. **`.sonarlint/connectedMode.json`** - Look for:
   - `sonarQubeUri` or `serverUrl` (SONARQUBE_URL)
   - `token` (SONARQUBE_TOKEN)
   - `projectKey`

3. **`sonar-project.properties`** - Look for:
   - `sonar.host.url` (SONARQUBE_URL)
   - `sonar.login` or `sonar.token` (SONARQUBE_TOKEN)
   - `sonar.projectKey`

**Configuration Priority:**
- Use environment variables if found (highest priority)
- Fall back to `.sonarlint/connectedMode.json` if env vars not available
- Fall back to `sonar-project.properties` if neither above are available

After gathering available values:
- If all required values (URL, token, projectKey) are found: use them automatically without asking
- If only some values are found: present them to the user with AskUserQuestion and ask to confirm or fill in missing values
- If no values are found: ask user to provide all values

### 2. Retrieve SAST Issues

1. Check if `sonar_issues.json` exists in the current directory
2. If it exists:
   - Ask user if they want to use this file or fetch fresh data
3. If not exists or user wants fresh data:
   - Use the SonarQube API to fetch issues:
     ```
     GET {SONARQUBE_URL}/api/issues/search?componentKeys={projectKey}&statuses=OPEN,CONFIRMED,REOPENED&ps=500
     ```
   - Save the response to `sonar_issues.json`
   - Handle pagination if more than 500 issues exist

**CRITICAL: Filter out imported DAST issues from SAST data**

4. After loading `sonar_issues.json`, filter out any issues with rules starting with `external_StackHawk:` or other external tool prefixes
   - These are DAST findings that were imported into SonarQube
   - Only keep TRUE SAST issues (code analysis findings)
   - Track how many issues were filtered for reporting
   - Example: If there are 24 total issues and 12 are `external_StackHawk:*`, keep only the 12 true SAST issues

### 3. Retrieve DAST Issues

1. Search for all `*.sarif` files in the current directory using Glob
2. Present the list to the user with AskUserQuestion:
   - Show file names, sizes, and modification dates
   - Allow user to select one file
   - Provide option to enter a custom file path
3. Parse the selected SARIF file to extract:
   - Tool name (from `runs[0].tool.driver.name`)
   - Scan information (from `runs[0].automationDetails` if available)
   - All findings/results with their severity levels

### 4. Deep Correlation Analysis

**IMPORTANT: Use the Agent tool for correlation, NOT simple Python scripts**

Use the `Agent` tool with `subagent_type: "general-purpose"` to perform deep, intelligent correlation analysis:

```
Agent with prompt:
"Perform in-depth correlation analysis between SAST findings from sonar_issues.json
and DAST findings from {selected_sarif_file}.

**MANDATORY RULE: ONLY create correlations between SAST and DAST findings that are the SAME vulnerability category.**
**This rule ALWAYS applies - there are NO exceptions.**

Read both files and identify correlations by:
1. **MANDATORY FIRST STEP:** Verify vulnerability categories match
   - SAST and DAST findings MUST be the same category (SQL Injection, XSS, Path Traversal, etc.)
   - Use CWE numbers if available in both sources (exact or related CWE match)
   - If CWE not available, extract category from rule names, titles, descriptions
   - Examples of VALID correlations: SQL Injection ↔ SQL Injection, XSS ↔ XSS, Path Traversal ↔ Path Traversal
   - Examples of INVALID correlations: SQL Injection ↔ XSS, Path Traversal ↔ CSRF, XSS ↔ Security Headers
   - **SKIP to next finding** if categories don't match - DO NOT create a correlation
2. Matching code paths to endpoints (e.g., SearchRepository.java → /search endpoint)
3. Analyzing taint flows from SAST and matching to exploited endpoints in DAST

**Remember: Better to return ZERO correlations than to create even ONE false correlation between different vulnerability types.**

For each correlation found, provide:
- SAST issue details (rule, file, line, message, taint flow, CWE if available)
- DAST issue details (rule, URI, method, severity, CWE if available)
- Detailed correlation reasoning explaining WHY they match (including category/CWE match)
- Confidence level (high/medium/low)

Output to correlations.json with structure:
{
  'correlations': [
    {
      'sast_issue_key': '...',
      'sast_rule': '...',
      'sast_component': '...',
      'sast_line': ...,
      'sast_message': '...',
      'sast_severity': '...',
      'sast_flow_summary': '...',
      'sast_cwe': '...' (if available, e.g., 'CWE-89'),
      'sast_category': '...' (vulnerability type: 'SQL Injection', 'XSS', etc.),
      'dast_rule_id': '...',
      'dast_uri': '...',
      'dast_method': '...',
      'dast_message': '...',
      'dast_level': '...',
      'dast_cwe': '...' (if available in SARIF, e.g., 'CWE-89'),
      'dast_category': '...' (vulnerability type extracted from rule/title),
      'correlation_reasoning': 'Detailed explanation including why categories match...',
      'confidence': 'high|medium|low'
    }
  ],
  'summary': {
    'total_correlations': ...,
    'vulnerability_types_correlated': [...]
  }
}"
```

**Correlation Strategies the Agent MUST use:**

**⚠️ MANDATORY REQUIREMENT - ALWAYS ENFORCED: Only correlate findings with matching vulnerability categories!**

**This is NOT conditional - this requirement applies to EVERY correlation attempt, regardless of how many correlations are found.**

0. **Category/CWE Validation** (MANDATORY FIRST STEP FOR EVERY POTENTIAL CORRELATION):
   - **ALWAYS verify that SAST and DAST findings are the SAME vulnerability type/category**
   - This verification happens BEFORE any other matching logic
   - Check CWE numbers first if both sources provide them (e.g., CWE-89 for SQL Injection)
   - If CWE not available, extract category from: rule IDs, rule names, issue titles, descriptions, tags
   - **ABSOLUTE RULE: DO NOT correlate different vulnerability types**
   - **DO NOT correlate** SQL Injection with XSS, even if they're in the same file
   - **DO NOT correlate** Path Traversal with CSRF, even if they share an endpoint
   - **DO NOT correlate** Command Injection with Security Headers, ever
   - **REJECT and SKIP** any correlation where categories don't match, even if endpoints align perfectly
   - Example VALID matches: SQL Injection ↔ SQL Injection, XSS ↔ XSS, Path Traversal ↔ Path Traversal
   - Example INVALID matches (NEVER create these): SQL Injection ↔ XSS, CSRF ↔ Path Traversal, XSS ↔ Security Headers

1. **Vulnerability Type Matching** (PRIMARY - after category validation):
   - SQL Injection: `javasecurity:S3649`, `java:S2077` ↔ `sql-injection`, CWE-89
   - XSS: `javasecurity:S5131` ↔ `cross-site-scripting-reflected`, `cross-site-scripting`, CWE-79
   - Path Traversal: `javasecurity:S2083` ↔ `path-traversal`, `directory-traversal`, CWE-22
   - XXE: `java:S2755` ↔ `xxe`, `xml-external-entity`, CWE-611
   - Command Injection: ↔ `command-injection`, CWE-78
   - CSRF: ↔ `csrf`, CWE-352

2. **Endpoint/Component Mapping** (SECONDARY):
   - Match controller class names to URI paths
   - Example: `SearchRepository.java` used by `HomeController POST "/"` ↔ DAST finding at `POST /`
   - Example: `ProductController.java GET "/products/direct"` ↔ DAST finding at `GET /products/direct`

3. **Taint Flow Analysis** (TERTIARY):
   - Examine SAST taint flows (source → sink)
   - Match source (@RequestParam, @PathVariable) to DAST request parameters
   - Match sink (SQL query, HTML output, file operations) to DAST vulnerability type
   - Verify sink type aligns with vulnerability category (e.g., SQL sink → SQL Injection category)

4. **Confidence Scoring** (only applies to correlations with matching categories):
   - **PREREQUISITE**: Same vulnerability category (if categories don't match, REJECT - don't score)
   - HIGH: Same vulnerability category + matching endpoint/component + taint flow aligns
   - MEDIUM: Same vulnerability category + partial component match OR endpoint match
   - LOW: Same vulnerability category only, no endpoint/component match
   - **NO CORRELATION**: Different vulnerability categories (immediately reject, do not create correlation)

### 5. Generate Markdown Report

Create a comprehensive report: `sast-dast-correlation-report.md`

**Icon Mapping (Severity-Based):**

Use icons based on SAST severity levels (NOT vulnerability type):
- 🔴 Red = BLOCKER or CRITICAL severity
- 🟠 Orange = MAJOR or HIGH severity
- 🟡 Yellow = MINOR or MEDIUM severity
- 🔵 Blue = INFO or LOW severity

**Report Structure:**

```markdown
# SonarQube SAST-DAST Correlation Report

**Generated:** {timestamp}
**Project:** {projectKey}

## Executive Summary

- **SAST Tool:** SonarQube ([{SONARQUBE_URL}]({SONARQUBE_URL}))
- **DAST Tool:** {tool name from SARIF} ([Scan Results]({scan_uri}))
- **Total SAST Issues:** {count} *(filtered out {n} imported DAST issues)*
- **Total DAST Issues:** {count}
- **✅ Correlated Issues:** {count} **HIGH CONFIDENCE**
- **SAST-Only Issues:** {count}
- **DAST-Only Issues:** {count}

## Severity Distribution

| Severity Level | SAST Count | DAST Count | Correlated |
|----------------|------------|------------|------------|
| Critical/Error | {n} | {n} | {n} ✅ |
| High/Warning | {n} | {n} | {n} |
| Medium/Note | {n} | {n} | {n} |
| Low/Info | {n} | {n} | {n} |

## 🔥 Correlated Findings - HIGH PRIORITY

**{count} critical vulnerabilities** confirmed by BOTH static and dynamic analysis.

⚠️ **These issues have the highest confidence and should be fixed immediately.** Both SAST and DAST independently discovered these vulnerabilities, confirming they are real, exploitable security flaws.

---

{For each correlated issue:}

### {icon} Correlation #{n}: {Vulnerability Type}

#### SAST Finding (Code Analysis)

- **Rule:** `{rule}`
- **Severity:** {severity} {icon}
- **File:** `{component}`
- **Line:** {line}
- **Issue:** {message}
- **Taint Flow:** {taint flow summary showing source → sink}
- 🔗 **[View in SonarQube]({SONARQUBE_URL}/project/issues?id={projectKey}&issues={issue_key}&open={issue_key})**

#### DAST Finding (Runtime Testing)

- **Rule:** `{ruleId}`
- **Severity:** {level}
- **Method:** {HTTP method}
- **Endpoint:** `{URI}`
- **Issue:** {message}
- 🔗 **[View in {tool name}]({helpUri})**

#### Why These Correlate

{Detailed correlation reasoning from Agent analysis}

**Confidence Level:** {confidence} ✅

---

## SAST-Only Findings

Issues found only by static analysis (may not be exploitable in runtime):

{For each SAST-only issue, grouped by severity:}

### {Severity Level}

| Rule | Component | Message | Link |
|------|-----------|---------|------|
| {rule} | {component} | {message} | [View]({link}) |

## DAST-Only Findings

Issues found only by dynamic analysis (may indicate runtime-specific vulnerabilities):

{For each DAST-only issue, grouped by severity:}

### {Severity Level}

| Rule | Location | Message | Link |
|------|----------|---------|------|
| {ruleId} | {URI} | {message} | [View]({link}) |

## Coverage Analysis

### Vulnerability Categories Covered

- **SQL Injection:** SAST ✓ | DAST ✓
- **XSS:** SAST ✓ | DAST ✓
- **CSRF:** SAST ✗ | DAST ✓
- {etc...}

## Recommendations

### 🔥 IMMEDIATE ACTION REQUIRED

1. **Fix the {n} correlated vulnerabilities FIRST** - These are confirmed exploitable:
   {List each correlation with file name and line number}

### Priority Actions

2. **🔴 Remaining Critical SAST Issues**: Address {n} code-level vulnerabilities
3. **⚠️ DAST Runtime Issues**: Fix {n} runtime configuration issues (headers, cookies, CSRF)

### Analysis Insights

- **Correlation Success**: {n} out of {total} SAST issues confirmed exploitable ({%} validation rate)
- **SAST Coverage**: Found code-level issues not detectable at runtime (path traversal, XXE, etc.)
- **DAST Coverage**: Found {n} runtime configuration issues invisible to static analysis
- **Complementary Testing**: Both tools provide essential, non-overlapping coverage

## Detailed Findings

### All SAST Issues

{Expandable/collapsible section with full SAST issue list}

### All DAST Issues

{Expandable/collapsible section with full DAST issue list}

---

*Report generated by Claude Code SonarQube SAST-DAST Correlation Skill*
```

## Tools Available

- **Read**: Read configuration files and issue data
- **Write**: Create the correlation report
- **Bash**: Execute SonarQube API calls with curl, filter SAST issues, and open the report in the default browser
- **Glob**: Find SARIF files
- **Grep**: Search for configuration values
- **AskUserQuestion**: Confirm configuration and file selections
- **Agent**: Perform deep correlation analysis (REQUIRED - use general-purpose agent)

## Error Handling

- If SonarQube API is unreachable, inform the user and offer to work with existing `sonar_issues.json`
- If no SARIF files are found, inform the user and ask for a file path
- Validate SARIF file format before processing
- Remember to filter out `external_StackHawk:` or similar imported issues from SAST data
- If correlation produces unexpectedly zero matches, verify that SAST and DAST scanned the same application (the most common reason is they scanned different apps or found completely different vulnerability categories)

## Output Files

- `sonar_issues.json` - SAST issues from SonarQube (if created)
- `correlations.json` - Correlation analysis results from Agent (intermediate file)
- `sast-dast-correlation-report.md` - Final correlation report with detailed findings

## Implementation Workflow

When executing this skill:

1. **Check for Existing Report** - Look for `sast-dast-correlation-report.md` and ask if user wants to open it or rerun analysis
2. **Gather Configuration** - Check environment variables FIRST (`env | grep -i sonar`), then read `.sonarlint/connectedMode.json` if needed, use values automatically if all are found
3. **Find SARIF Files** - Use Glob to find `*.sarif` files and ask user which to use
4. **Check for Existing Data** - Look for `sonar_issues.json` and ask if user wants to use it or fetch fresh
5. **Filter SAST Issues** - Remove `external_StackHawk:*` rules from SAST data using Bash/Python
6. **Run Agent Analysis** - Use Agent tool (general-purpose) to create `correlations.json`
7. **Generate Report** - Use the correlations.json + filtered data to create the final markdown report
8. **Open Report in Browser** - Automatically open `sast-dast-correlation-report.md` in the default browser:
   - macOS: `open sast-dast-correlation-report.md`
   - Linux: `xdg-open sast-dast-correlation-report.md`
   - Windows: `start sast-dast-correlation-report.md`
9. **Inform User** - Tell user about correlations found and that the report has been opened in their browser
10. **Tag Correlated Issues (Optional)** - After opening the report, follow this multi-step process:

    **Step 10a: Ask User About Tagging**
    - Use AskUserQuestion to ask if user wants to tag the correlated issues on SonarQube
    - If user declines, skip the rest of step 10
    - If user agrees, proceed to Step 10b

    **Step 10b: Ask About Clearing Existing Tags**
    - Use AskUserQuestion to ask: "Should I clear existing 'dast-detected' tags and correlation comments before applying new ones?"
    - **If user agrees to clear:**
      1. Fetch all issues with 'dast-detected' tag using SonarQube API:
         ```bash
         curl -u "$SONAR_TOKEN:" "{SONARQUBE_URL}/api/issues/search?componentKeys={projectKey}&tags=dast-detected&ps=500"
         ```
      2. For each issue found:
         - Get the issue details including comments
         - **IMPORTANT:** Find and delete **ALL** comments that contain "DAST Correlation" (search for 🔴, 🟠, 🟡, 🔵 icons or "DAST Correlation" text)
         - **CRITICAL:** Collect ALL matching comment keys FIRST, then delete them ALL in sequence
         - Do NOT stop after deleting the first matching comment - an issue may have multiple old correlation comments that all need to be removed
         - For each matching comment, delete using:
           ```bash
           curl -u "$SONAR_TOKEN:" -X POST "{SONARQUBE_URL}/api/issues/delete_comment" \
             -d "comment={comment_key}"
           ```
         - After deleting all correlation comments, remove the 'dast-detected' tag using:
           ```bash
           curl -u "$SONAR_TOKEN:" -X POST "{SONARQUBE_URL}/api/issues/set_tags" \
             -d "issue={issue_key}" \
             -d "tags="
           ```
      3. Report how many issues were cleared and how many total comments were deleted
    - **If user declines to clear:**
      - Skip clearing steps and proceed directly to Step 10c
      - Inform user that new tags will be added alongside any existing tags

    **Step 10c: Tag New Correlations**
    - **CRITICAL:** Use the SonarQube URL and token from step 1 (environment variables or config files)
    - Check environment variables again if needed: `SONAR_TOKEN` or `SONARQUBE_TOKEN`, `SONARQUBE_URL` or `SONAR_HOST_URL`
    - For each newly correlated issue from correlations.json:
      - Add tag "dast-detected" using SonarQube API with curl:
        ```bash
        curl -u "$SONAR_TOKEN:" -X POST "{SONARQUBE_URL}/api/issues/set_tags" \
          -d "issue={issue_key}" \
          -d "tags=dast-detected"
        ```
      - Add a comment with correlation details using SonarQube API:
        ```bash
        curl -u "$SONAR_TOKEN:" -X POST "{SONARQUBE_URL}/api/issues/add_comment" \
          -d "issue={issue_key}" \
          --data-urlencode "text={correlation_details}"
        ```
      - The comment should include:
        - {icon} DAST Correlation - HIGH CONFIDENCE header (icon based on SAST severity: 🔴=BLOCKER/CRITICAL, 🟠=MAJOR/HIGH, 🟡=MINOR/MEDIUM, 🔵=INFO/LOW)
        - Vulnerability type (SQL Injection, XSS, etc.)
        - SAST severity level
        - Correlation confidence level
        - DAST tool and finding details
        - Correlation reasoning (from the markdown report)
        - Link to the DAST finding
    - **Authentication:** Use `curl -u "$SONAR_TOKEN:"` (token as username, empty password) for API calls
    - Report success/failure for each tagging operation
    - Provide summary of:
      - How many existing tags were cleared (if applicable)
      - How many new issues were tagged successfully
      - Total issues now tagged with 'dast-detected'

## Example Usage

User: "Correlate my security findings"
User: "Generate a SAST-DAST correlation report"
User: "Compare SonarQube and StackHawk results"

## Key Success Factors

✅ **CRITICAL: Validate category/CWE matching FIRST** - Only correlate SAST and DAST findings if they are the SAME vulnerability type (SQL Injection ↔ SQL Injection, NOT SQL Injection ↔ XSS). Use CWE numbers or extract category from rule names/titles/descriptions. Reject correlations with different categories.
✅ **Check environment variables FIRST** - Use `env | grep -i sonar` to find `SONAR_TOKEN`, `SONARQUBE_TOKEN`, `SONARQUBE_URL`, etc. before reading config files
✅ **Filter out imported DAST issues** from SonarQube data before analysis
✅ **Use Agent tool** for correlation - it provides deeper reasoning than simple scripts
✅ **Match vulnerability types precisely** - SQL injection to sql-injection, XSS to cross-site-scripting (category must match!)
✅ **Trace code paths to endpoints** - SearchRepository.java → POST / endpoint (secondary to category matching)
✅ **Use severity-based icons** - 🔴 BLOCKER/CRITICAL, 🟠 MAJOR/HIGH, 🟡 MINOR/MEDIUM, 🔵 INFO/LOW (NOT based on vulnerability type)
✅ **Emphasize correlated findings** - these have highest confidence and priority
✅ **Provide direct links** to both SonarQube and DAST tool UIs for each issue
✅ **Use detected credentials automatically** - When all required config values are found (URL, token, projectKey), use them without asking the user
✅ **Prevent false correlations** - Better to have NO correlation than a wrong correlation between different vulnerability types
