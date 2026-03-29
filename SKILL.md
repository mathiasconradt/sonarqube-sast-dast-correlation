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

### 4. Deep Correlation Analysis with Source Code Analysis

**CRITICAL: The skill runs inside the project folder with full access to source code. USE THIS!**

**IMPORTANT: Use the Agent tool for correlation, NOT simple Python scripts**

Use the `Agent` tool with `subagent_type: "general-purpose"` to perform deep, intelligent correlation analysis:

```
Agent with prompt:
"Perform in-depth correlation analysis between SAST findings from sonar_issues.json
and DAST findings from {selected_sarif_file}.

**MANDATORY RULES:**
1. ONLY create correlations between SAST and DAST findings that are the SAME vulnerability category
2. ONLY correlate if the DAST URL actually maps to the code location of the SAST issue
3. You have full access to the project source code - READ THE ACTUAL FILES to verify correlations

**CORRELATION PROCESS - FOLLOW STRICTLY:**

For each SAST issue:

STEP 1: **Read the Source File**
   - Use Read tool to read the file mentioned in the SAST issue (e.g., ProductController.java)
   - Find the vulnerable line number from the SAST issue
   - Identify the controller method containing this line
   - Extract the endpoint mapping from annotations:
     * @RequestMapping("/path")
     * @GetMapping("/path")
     * @PostMapping("/path")
     * @PutMapping, @DeleteMapping, @PatchMapping
     * Look for both class-level and method-level mappings (they combine!)
   - Identify parameter names from:
     * @RequestParam("paramName")
     * @PathVariable("varName")
     * @RequestBody fields
     * Method parameter names

STEP 2: **Map Endpoint to URL**
   - Combine class-level and method-level mappings
   - Example: Class has @RequestMapping("/products"), method has @GetMapping("/direct")
   - Full endpoint: /products/direct
   - Note the HTTP method (GET, POST, etc.)

STEP 3: **Find Matching DAST Findings**
   - Look through DAST findings for URLs that match this endpoint
   - URL matching rules:
     * Exact match: DAST URL "/products/direct" matches endpoint "/products/direct"
     * Parameter match: DAST URL "/products/direct?param=value" matches endpoint "/products/direct"
     * Path variable match: DAST URL "/users/123" matches endpoint "/users/{id}"
     * Base URL variations: Strip protocol and domain, match path only
   - HTTP method MUST match (GET to GET, POST to POST)

STEP 4: **Verify Vulnerability Category Match**
   - SAST and DAST findings MUST be the same category (SQL Injection, XSS, Path Traversal, etc.)
   - Use CWE numbers if available in both sources (exact or related CWE match)
   - If CWE not available, extract category from: rule IDs, rule names, issue titles, descriptions, tags
   - Examples of VALID correlations: SQL Injection ↔ SQL Injection, XSS ↔ XSS, Path Traversal ↔ Path Traversal
   - Examples of INVALID correlations: SQL Injection ↔ XSS, Path Traversal ↔ CSRF, XSS ↔ Security Headers
   - **REJECT if categories don't match** - DO NOT create a correlation

STEP 5: **Verify Data Flow**
   - Read the SAST taint flow details
   - Check if the vulnerable parameter in the code matches the parameter DAST tested
   - Example: If SAST shows @RequestParam("param") is vulnerable, verify DAST tested "?param=..."
   - For POST requests, check if the vulnerable field matches the POST body parameter
   - Trace the data flow: source (request param) → sink (SQL query, HTML output, file operation)

STEP 6: **Assign Confidence Level**
   - **HIGH**: Same category + exact URL match + same HTTP method + parameter match + data flow verified
   - **MEDIUM**: Same category + URL match + same HTTP method (but parameters unclear)
   - **LOW**: Same category only, URL might be related but not exact match
   - **NO CORRELATION**: Different categories OR URL doesn't match OR wrong HTTP method

STEP 7: **Document the Correlation**
   - Explain exactly which endpoint in the code maps to which DAST URL
   - Show the controller annotation → endpoint mapping
   - Explain the parameter flow
   - Provide file:line references

**EXAMPLES OF GOOD CORRELATIONS:**

✅ CORRECT:
- SAST: ProductController.java:101, @GetMapping("/products/direct"), @RequestParam("param"), XSS vulnerability
- DAST: GET /products/direct?param=<script>alert(1)</script>, XSS detected
- Reasoning: "Exact endpoint match (/products/direct), same HTTP method (GET), vulnerable parameter 'param' was tested with XSS payload, same vulnerability category (XSS)"

✅ CORRECT:
- SAST: SearchRepository.java:23, used by HomeController @PostMapping("/"), SQL injection in search parameter
- DAST: POST / with body param "search='; DROP TABLE--", SQL injection detected
- Reasoning: "Endpoint match (POST /), SearchRepository.findBySearch() is called from HomeController.search(), parameter matches, same vulnerability (SQL injection)"

❌ INCORRECT:
- SAST: ProductController.java:101, @GetMapping("/products/direct"), XSS vulnerability
- DAST: POST /login, Cookie security issue
- Why wrong: Different endpoints, different HTTP methods, different vulnerability categories

❌ INCORRECT:
- SAST: UserController.java:50, @PostMapping("/users"), SQL injection
- DAST: GET /products/direct?param=<script>, XSS
- Why wrong: Completely different endpoints AND different vulnerability categories

**Remember: Better to return ZERO correlations than to create even ONE false correlation!**

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
      'sast_endpoint': '...' (extracted from source code, e.g., 'GET /products/{id}'),
      'sast_controller_method': '...' (method name from source, e.g., 'ProductController.getProduct()'),
      'sast_parameter': '...' (vulnerable parameter from source, e.g., '@RequestParam("query")'),
      'dast_rule_id': '...',
      'dast_uri': '...',
      'dast_method': '...',
      'dast_message': '...',
      'dast_level': '...',
      'dast_cwe': '...' (if available in SARIF, e.g., 'CWE-89'),
      'dast_category': '...' (vulnerability type extracted from rule/title),
      'dast_tested_parameter': '...' (parameter tested by DAST, extracted from URI or body),
      'endpoint_match': 'exact|partial|none' (how well the endpoints match),
      'parameter_match': true|false (whether parameters match),
      'http_method_match': true|false (whether HTTP methods match),
      'correlation_reasoning': 'Detailed explanation including:
        - Why vulnerability categories match (with CWE)
        - How endpoints map from source code to DAST URL
        - Why parameters match or don't match
        - Source code evidence (file:line, annotations)
        - Data flow verification',
      'confidence': 'high|medium|low',
      'source_code_verified': true|false (whether source code was actually read)
    }
  ],
  'summary': {
    'total_correlations': ...,
    'high_confidence_correlations': ...,
    'medium_confidence_correlations': ...,
    'low_confidence_correlations': ...,
    'vulnerability_types_correlated': [...],
    'source_files_analyzed': [...],
    'rejected_due_to_endpoint_mismatch': ...,
    'rejected_due_to_category_mismatch': ...,
    'rejected_due_to_http_method_mismatch': ...
  }
}"
```

**Source Code Analysis Workflow:**

**⚠️ CRITICAL: You MUST read the actual source files to verify endpoint mappings!**

For each SAST issue, follow this workflow:

1. **Read the Controller/Service File**
   ```
   Use Read tool on the file from SAST issue's 'component' field
   Example: if component is "...controller/ProductController.java", read that file
   ```

2. **Find the Vulnerable Code**
   - Locate the line number from the SAST issue
   - Identify the containing method
   - Extract controller annotations (@GetMapping, @PostMapping, etc.)
   - Identify parameter annotations (@RequestParam, @PathVariable, @RequestBody)

3. **Map the Endpoint**
   - Combine class-level @RequestMapping with method-level mapping
   - Example:
     ```java
     @RestController
     @RequestMapping("/api/products")  // Class level
     public class ProductController {
         @GetMapping("/{id}")  // Method level
         public Product getProduct(@PathVariable String id) {
             // Full endpoint: GET /api/products/{id}
         }
     }
     ```

4. **Find Files That Call This Code** (for Repository/Service classes)
   - If SAST issue is in a Repository or Service class (not a Controller):
     * Use Grep to search for method calls to this class
     * Find which Controller calls this Repository/Service
     * Read that Controller to get the endpoint
   - Example: SearchRepository.findByName() → Used by HomeController.search() → POST /search

5. **Match Against DAST URLs**
   - Extract path from DAST URI (strip protocol, domain, query params)
   - Compare with endpoint from source code
   - Verify HTTP method matches
   - Check if parameters in DAST request match code parameters

**Correlation Validation Rules:**

**⚠️ MANDATORY: All conditions must be true for a valid correlation:**

✅ **Category Match** (MANDATORY - ALWAYS CHECK FIRST):
   - SAST and DAST MUST be the same vulnerability type
   - Check CWE numbers first (e.g., CWE-89 for SQL Injection)
   - If no CWE, extract from rule names/descriptions
   - SQL Injection ↔ SQL Injection ✅
   - XSS ↔ XSS ✅
   - SQL Injection ↔ XSS ❌ REJECT
   - Path Traversal ↔ CSRF ❌ REJECT

✅ **Endpoint Match** (MANDATORY - READ SOURCE CODE):
   - DAST URL path must match the endpoint from source code annotations
   - HTTP method must match (GET, POST, PUT, DELETE, etc.)
   - Examples:
     * Code: @GetMapping("/products/{id}") → DAST: GET /products/123 ✅
     * Code: @PostMapping("/search") → DAST: POST /search ✅
     * Code: @GetMapping("/users") → DAST: POST /login ❌ REJECT

✅ **Parameter Match** (HIGHLY RECOMMENDED):
   - Vulnerable parameter in code should match tested parameter in DAST
   - Code: @RequestParam("query") → DAST: ?query=<malicious> ✅
   - Code: @PathVariable("id") → DAST: /users/123 ✅
   - If parameters don't match, lower confidence or reject

✅ **Data Flow Verification** (RECOMMENDED):
   - Verify the code path from SAST actually handles the request
   - For Repository/Service classes: verify a Controller calls this code
   - Trace: HTTP Request → Controller Method → Service/Repository Method → Vulnerable Line

**Confidence Levels (after all validations pass):**

- **HIGH**: Category match + exact endpoint match + HTTP method match + parameter match + data flow verified
- **MEDIUM**: Category match + endpoint match + HTTP method match (parameters unclear or don't match exactly)
- **LOW**: Category match + similar endpoint (might be related) + HTTP method match
- **REJECT**: Any of the following:
  * Different vulnerability categories
  * Endpoints don't match at all
  * HTTP methods don't match
  * Clear evidence the code path isn't related to the DAST finding

**Vulnerability Type Reference:**

- SQL Injection: `javasecurity:S3649`, `java:S2077` ↔ `40018`, `sql-injection`, CWE-89
- XSS: `javasecurity:S5131` ↔ `40012`, `40014`, `cross-site-scripting`, CWE-79
- Path Traversal: `javasecurity:S2083` ↔ `path-traversal`, `directory-traversal`, CWE-22
- XXE: `java:S2755` ↔ `xxe`, `xml-external-entity`, CWE-611
- Command Injection: ↔ `command-injection`, `90020`, CWE-78
- CSRF: ↔ `csrf`, `40016`, CWE-352

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

✅ **CRITICAL: READ THE SOURCE CODE** - The skill runs inside the project folder with full access to source code. ALWAYS read controller/service files to verify endpoint mappings before creating correlations. Use the Read tool to examine actual code.

✅ **CRITICAL: Validate endpoint mapping** - DAST URL must map to the actual endpoint defined in the source code:
   - Read the controller file from the SAST issue
   - Extract @GetMapping, @PostMapping, @RequestMapping annotations
   - Combine class-level and method-level mappings
   - Verify DAST URL matches this endpoint
   - Verify HTTP method matches (GET, POST, etc.)
   - **REJECT if endpoints don't match** - even if vulnerability categories match!

✅ **CRITICAL: Validate category/CWE matching** - Only correlate SAST and DAST findings if they are the SAME vulnerability type:
   - SQL Injection ↔ SQL Injection ✅
   - XSS ↔ XSS ✅
   - SQL Injection ↔ XSS ❌ REJECT
   - Use CWE numbers or extract category from rule names/titles/descriptions
   - **REJECT correlations with different categories** - this is non-negotiable

✅ **CRITICAL: Verify parameter flow** - Match the vulnerable parameter in code to the parameter DAST tested:
   - If SAST shows @RequestParam("query") is vulnerable, DAST should test "?query=..."
   - If SAST shows @PathVariable("id"), DAST should test the path variable
   - Read the actual code to see parameter annotations

✅ **CRITICAL: Trace data flow for Repository/Service classes** - If SAST issue is not in a Controller:
   - Use Grep to find which Controller calls this Repository/Service method
   - Read that Controller to get the endpoint
   - Verify the data flows from HTTP request → Controller → Repository/Service → Vulnerable line

✅ **Check environment variables FIRST** - Use `env | grep -i sonar` to find `SONAR_TOKEN`, `SONARQUBE_TOKEN`, `SONARQUBE_URL`, etc. before reading config files

✅ **Filter out imported DAST issues** from SonarQube data before analysis (rules starting with `external_`)

✅ **Use Agent tool** for correlation - it provides deeper reasoning and can read source files during analysis

✅ **Use severity-based icons** - 🔴 BLOCKER/CRITICAL, 🟠 MAJOR/HIGH, 🟡 MINOR/MEDIUM, 🔵 INFO/LOW (NOT based on vulnerability type)

✅ **Emphasize correlated findings** - these have highest confidence and priority (both SAST and DAST confirmed)

✅ **Provide direct links** to both SonarQube and DAST tool UIs for each issue

✅ **Use detected credentials automatically** - When all required config values are found (URL, token, projectKey), use them without asking the user

✅ **Prevent false correlations** - Better to return ZERO correlations than to create even ONE false correlation:
   - Don't correlate different vulnerability types
   - Don't correlate different endpoints
   - Don't correlate different HTTP methods
   - When in doubt, read the source code to verify
