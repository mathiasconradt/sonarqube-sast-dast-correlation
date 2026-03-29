# SonarQube + ZAP Correlation Example

This example demonstrates a real-world correlation analysis between SonarQube SAST findings and OWASP ZAP DAST scan results.

## Overview

This correlation was performed on a Java Spring Boot application with intentional security vulnerabilities for testing purposes.

### Test Application Details

- **Language**: Java
- **Framework**: Spring Boot
- **SAST Tool**: SonarQube (with SonarJava security rules)
- **DAST Tool**: OWASP ZAP (Zed Attack Proxy)
- **Scan Date**: March 29, 2026

## Key Findings

### 2 HIGH CONFIDENCE Correlations

Both SAST and DAST independently detected these vulnerabilities, confirming they are **exploitable in runtime**:

1. **SQL Injection** - `SearchRepository.java:23`
   - **SAST Rule**: `javasecurity:S3649`
   - **DAST Finding**: Rule `40018` at `POST /`
   - **Confidence**: HIGH ✅
   - **Attack Payload**: `input='` (triggered HTTP 500 error)
   - **Reason**: Exact endpoint match + complete taint flow from HTTP request to SQL query + ZAP successfully exploited

2. **Cross-Site Scripting (XSS)** - `ProductController.java:101`
   - **SAST Rule**: `javasecurity:S5131`
   - **DAST Finding**: Rule `40012` at `GET /products/direct`
   - **Confidence**: HIGH ✅
   - **Attack Payload**: `</h1><scrIpt>alert(1);</scRipt><h1>` (successfully reflected in response)
   - **Reason**: Exact endpoint match + complete taint flow from HTTP parameter to HTML output + ZAP successfully exploited

### 2 SAST-Only Findings (Not Detected by ZAP)

Critical vulnerabilities found in code but not detected during DAST scanning:

3. **Path Traversal** - `OldUploadController.java:22`
   - **SAST Rule**: `javasecurity:S2083`
   - **Why Not Detected**: Endpoint may be inactive or ZAP scan didn't include file upload fuzzing

4. **XXE (XML External Entities)** - `XMLExporter.java:58`
   - **SAST Rule**: `java:S2755`
   - **Why Not Detected**: XML parsing endpoint may not be accessible or ZAP didn't include XXE payloads

## Files in This Example

### `sast-dast-correlation-report.md`

Complete correlation report including:
- Executive summary with metrics
- Detailed taint flow analysis for each correlation
- ZAP attack payloads and exploitation details
- SAST-only findings (100 code-level issues)
- DAST-only findings (40 runtime/configuration issues)
- Coverage analysis
- Prioritized remediation recommendations

### `correlations.json`

Machine-readable correlation data with:
- SAST issue details (rule, component, line, severity, detailed taint flow)
- DAST finding details (rule ID, URI, method, severity, attack payload)
- Detailed correlation reasoning
- Confidence levels
- Remediation notes
- Summary statistics

## Correlation Statistics

| Metric | Count |
|--------|-------|
| Total SAST Issues | 102 |
| SAST Issues (after filtering) | 102 |
| External Issues Filtered | 12 |
| Total DAST Issues | 42 |
| High Confidence Correlations | 2 |
| SAST-Only Issues | 100 |
| DAST-Only Issues | 40 |

### Severity Breakdown

| Severity | SAST | DAST | Correlated |
|----------|------|------|------------|
| Critical | 20 | 2 | 2 ✅ |
| High | 52 | 16 | 0 |
| Medium | 28 | 2 | 0 |
| Low | 2 | 22 | 0 |

## Correlation Insights

### Why Only 2 Correlations?

The 2% correlation rate (2 out of 102 SAST issues) is **typical and expected**:

- **SAST detects potential vulnerabilities** - Code patterns that *could* be exploited
- **DAST confirms actual exploitability** - Vulnerabilities that *are* exploitable at runtime
- **Correlated = Highest Priority** - When both tools agree, it's a confirmed security risk

### SAST-Only Findings (100 issues)

These code-level issues were not exploitable at runtime:
- Path traversal vulnerabilities (endpoint not active/reachable)
- XXE issues (XML parsing endpoint not tested)
- Other code quality and security anti-patterns
- Vulnerabilities in inactive code paths

### DAST-Only Findings (40 issues)

These runtime issues are not detectable by static analysis:
- Missing security headers (X-Frame-Options, CSP, etc.)
- CSRF protection gaps
- Session management issues
- Cookie security settings
- Server configuration issues

## Taint Flow Examples

### SQL Injection Taint Flow

```
SOURCE: HomeController.java:31 (HTTP POST request)
  ↓ @RequestParam String input from POST / endpoint
PROPAGATION: HomeController.java:32
  ↓ searchProducts() called with user input
PROPAGATION: SearchRepository.java:21-22
  ↓ User input converted to lowercase (insufficient sanitization)
SINK: SearchRepository.java:23 (SQL concatenation)
  ↓ Unsanitized input directly concatenated into SQL query
EXPLOIT: ZAP confirmed at POST / with payload: input='
  ↓ HTTP 500 error proves SQL injection vulnerability
```

### XSS Taint Flow

```
SOURCE: ProductController.java:71 (HTTP GET request)
  ↓ @RequestParam String param from GET /products/direct endpoint
PROPAGATION: ProductController.java:78-82
  ↓ Passes through method chain
SINK: ProductController.java:101 (HTML output)
  ↓ response.getWriter().println() writes unsanitized user input
EXPLOIT: ZAP confirmed at GET /products/direct
  ↓ Payload: </h1><scrIpt>alert(1);</scRipt><h1>
  ↓ Successfully reflected in HTTP 200 response
```

## ZAP-Specific Features Demonstrated

### Attack Payloads Documented

Unlike some DAST tools, this example shows the exact attack payloads ZAP used:
- **SQL Injection**: `input='` (single quote to trigger SQL error)
- **XSS**: `</h1><scrIpt>alert(1);</scRipt><h1>` (script injection with case variation)

### Exploitation Evidence

The correlation includes proof of exploitation:
- SQL Injection: HTTP 500 error confirms database error
- XSS: Payload reflected in HTTP 200 response body

### ZAP Scan Coverage

ZAP tested 42 different security scenarios, finding:
- 2 Critical vulnerabilities (correlated with SAST)
- 16 High-severity findings (mostly runtime configuration)
- 2 Medium-severity findings
- 22 Low-severity/informational findings

## How This Example Was Generated

1. **SonarQube Scan**:
   ```bash
   sonar-scanner \
     -Dsonar.projectKey=e-corp-demo \
     -Dsonar.sources=src \
     -Dsonar.host.url=https://mathiasconradt.ngrok.io \
     -Dsonar.login=$SONAR_TOKEN
   ```

2. **ZAP Scan**:
   ```bash
   # ZAP was configured to scan http://host.docker.internal:8081
   # Full active scan performed
   # Results exported to SARIF format: zap-full-report.json.sarif
   ```

3. **Correlation Analysis**:
   ```bash
   # In Claude Code
   /sonarqube-sast-dast-correlation
   # Selected: zap-full-report.json.sarif
   ```

## Comparison: ZAP vs. StackHawk

### ZAP Advantages

- **Open Source**: Free and community-driven
- **Detailed Attack Evidence**: Shows exact payloads used
- **Broad Coverage**: Tests many attack vectors (42 in this scan)
- **Flexible Configuration**: Highly customizable scan policies

### ZAP Characteristics

- **Attack Payloads**: More visible in findings (helps understand exploitation)
- **Scan Size**: Larger SARIF file (385K vs 60K for StackHawk)
- **Rule IDs**: Uses numeric rule IDs (40018, 40012)

### StackHawk Comparison

See the `../sonarqube-stackhawk-example/` for comparison. Key differences:
- StackHawk provides cloud-hosted findings dashboard
- StackHawk has more polished UI/reporting
- Both tools found the same 2 critical vulnerabilities
- ZAP provides more detailed attack payload information

## Key Takeaways

1. **Prioritization Works**: Focus on the 2 correlated HIGH CONFIDENCE vulnerabilities first
2. **Both Tools Are Necessary**: SAST and DAST find different vulnerability types
3. **ZAP Provides Proof**: Attack payloads demonstrate actual exploitability
4. **Taint Flow Analysis**: Understanding data flow validates correlations
5. **Confidence Scoring**: HIGH confidence = same vuln type + exact endpoint + taint flow match + successful exploitation

## Using This Example

This example can help you:
- Understand correlation between SonarQube and ZAP
- See how ZAP attack payloads are documented
- Learn how to interpret taint flow analysis
- Understand why correlation rates are typically low (2%)
- Compare ZAP findings with StackHawk (see sibling example)
- Get ideas for reporting to your security team

## Screenshots

### Correlation Report (HTML Rendering)

The generated markdown report rendered in a browser, showing the executive summary, correlated findings with ZAP attack payloads, and detailed taint flow analysis:

![Correlation Report HTML](correlation-report-html.png)

### SonarQube Tagged Issues

Correlated issues tagged with `dast-detected` in SonarQube, with detailed ZAP correlation comments including attack payloads:

![SonarQube DAST-Detected Issues](sonarqube-dast-detected-issues.png)

### Complete Example View

Full correlation analysis showing SonarQube SAST findings mapped to OWASP ZAP DAST results with exploitation evidence:

![SonarQube ZAP Example](sonarqube-zap-example.png)

## Related Examples

- **SonarQube + StackHawk**: See `../sonarqube-stackhawk-example/` for comparison
- **Examples Overview**: See `../README.md`

---

**Note**: This example uses a test application with intentional vulnerabilities. Always fix security issues in production code immediately.
