# SonarQube SAST-DAST Correlation Skill

> **⚠️ EXPERIMENTAL SKILL - USE AT YOUR OWN RISK**
>
> This is an experimental skill and repository. While it has been tested in development environments, it should be used with caution in production settings. The skill makes API calls to SonarQube and may modify issue tags and comments. Always review the actions before confirming, and test in a non-production environment first. The authors are not responsible for any unintended consequences or data loss.

A Claude Code skill that intelligently correlates Static Application Security Testing (SAST) findings from SonarQube with Dynamic Application Security Testing (DAST) findings from SARIF files (StackHawk, ZAP, etc.) to generate comprehensive security correlation reports.

## Overview

Security testing often involves running both SAST and DAST tools independently, but manually correlating their findings is time-consuming and error-prone. This skill automates the correlation process using AI-powered analysis to:

- **Match vulnerabilities** detected by both SAST and DAST tools
- **Validate exploitability** by confirming code-level issues are runtime-exploitable
- **Prioritize fixes** by highlighting vulnerabilities confirmed by both testing methods
- **Generate detailed reports** with taint flow analysis and direct links to findings
- **Tag correlated issues** in SonarQube for team tracking

## Key Features

### 🔍 Intelligent Correlation Analysis

- **Vulnerability Type Matching**: Maps SAST rules (e.g., `javasecurity:S3649`) to DAST findings (e.g., `sql-injection`)
- **Endpoint/Component Mapping**: Traces Java controller classes to URI paths
- **Taint Flow Analysis**: Matches data flow from HTTP requests to vulnerable sinks
- **Confidence Scoring**: HIGH/MEDIUM/LOW confidence levels based on multiple correlation factors

### 🎯 Supported Vulnerabilities

- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- XML External Entities (XXE)
- Command Injection
- And more...

### 📊 Comprehensive Reporting

- Executive summary with severity distribution
- Detailed correlation findings with HIGH CONFIDENCE markers
- SAST-only findings (code-level vulnerabilities)
- DAST-only findings (runtime/configuration issues)
- Coverage analysis showing complementary testing gaps
- Actionable recommendations prioritized by risk

### 🏷️ SonarQube Integration

- Automatically tags correlated issues with `dast-detected`
- Adds detailed correlation comments to SonarQube issues
- Includes taint flow analysis and DAST finding links
- Supports clearing old tags before applying new correlations

## Installation

### Prerequisites

- [Claude Code](https://claude.ai/code) (CLI, Desktop, or Web)
- SonarQube instance with API access
- DAST scan results in SARIF format (StackHawk, ZAP, etc.)

### Install the Skill

```bash
# Clone this repository to your Claude Code skills directory
cd ~/.claude/skills
git clone https://github.com/mathiasconradt/sonarqube-sast-dast-correlation.git

# Or manually download and extract to:
# ~/.claude/skills/sonarqube-sast-dast-correlation/
```

The skill will be automatically available in Claude Code after installation.

## Configuration

### SonarQube Credentials

The skill automatically detects SonarQube configuration from:

1. **Environment variables** (highest priority):
   ```bash
   export SONAR_TOKEN="your-sonarqube-token"
   export SONARQUBE_URL="https://your-sonarqube-instance.com"
   export SONAR_PROJECT_KEY="your-project-key"
   ```

2. **`.sonarlint/connectedMode.json`** in your project:
   ```json
   {
     "sonarQubeUri": "https://your-sonarqube-instance.com",
     "projectKey": "your-project-key"
   }
   ```

3. **`sonar-project.properties`** in your project:
   ```properties
   sonar.host.url=https://your-sonarqube-instance.com
   sonar.token=your-sonarqube-token
   sonar.projectKey=your-project-key
   ```

If credentials are not found, the skill will prompt you to provide them.

### DAST Scan Files

Place your DAST scan results (SARIF format) in your project directory. Supported tools:
- StackHawk (`.sarif`)
- OWASP ZAP (`.sarif`)
- Any SARIF-compliant scanner

## Usage

### Basic Usage

In Claude Code, navigate to your project directory and run:

```
/sonarqube-sast-dast-correlation
```

The skill will:
1. Detect SonarQube configuration automatically
2. Fetch SAST issues from SonarQube (or use cached `sonar_issues.json`)
3. List available SARIF files and ask you to select one
4. Perform deep AI-powered correlation analysis
5. Generate a comprehensive markdown report
6. Open the report in your browser
7. Optionally tag correlated issues in SonarQube

### Example Workflow

```bash
# 1. Run a SonarQube scan (if not already done)
sonar-scanner

# 2. Run a DAST scan (StackHawk example)
hawkscan

# 3. Navigate to your project directory
cd /path/to/your/project

# 4. Run the correlation skill in Claude Code
/sonarqube-sast-dast-correlation
```

### Interactive Prompts

The skill will guide you through:

1. **Existing Report**: Choose to open existing report or rerun analysis
2. **SAST Data**: Use cached `sonar_issues.json` or fetch fresh from SonarQube
3. **DAST File**: Select which SARIF file to correlate
4. **Tagging**: Optionally tag correlated issues in SonarQube
5. **Tag Cleanup**: Choose to clear existing tags before applying new ones

## Output Files

### `sast-dast-correlation-report.md`

Comprehensive correlation report with:
- Executive summary with key metrics
- Severity distribution table
- Detailed correlated findings (HIGH CONFIDENCE)
- SAST-only findings
- DAST-only findings
- Coverage analysis
- Prioritized recommendations

### `correlations.json`

Machine-readable correlation data:
```json
{
  "correlations": [
    {
      "sast_issue_key": "...",
      "sast_rule": "javasecurity:S3649",
      "sast_component": "SearchRepository.java",
      "sast_line": 23,
      "sast_message": "...",
      "sast_severity": "BLOCKER",
      "sast_flow_summary": "SOURCE: ... → SINK: ...",
      "dast_rule_id": "sql-injection",
      "dast_uri": "POST /",
      "dast_method": "POST",
      "dast_message": "...",
      "dast_level": "error",
      "correlation_reasoning": "...",
      "confidence": "high",
      "vulnerability_type": "SQL Injection"
    }
  ],
  "summary": {
    "total_correlations": 2,
    "high_confidence_count": 2,
    "vulnerability_types_correlated": ["SQL Injection", "XSS"]
  }
}
```

### `sonar_issues.json`

Cached SAST issues from SonarQube (filtered to exclude imported DAST findings).

## Example Report

```markdown
# SonarQube SAST-DAST Correlation Report

**Generated:** 2026-03-29
**Project:** my-awesome-app

## Executive Summary

- **SAST Tool:** SonarQube
- **DAST Tool:** StackHawk
- **Total SAST Issues:** 102
- **Total DAST Issues:** 49
- **✅ Correlated Issues:** 2 **HIGH CONFIDENCE**

## 🔥 Correlated Findings - HIGH PRIORITY

### 🚨 Correlation #1: SQL Injection

#### SAST Finding (Code Analysis)
- **File:** `SearchRepository.java:23`
- **Taint Flow:** HomeController.java:31 (user input) → SearchRepository.java:23 (SQL concatenation)
- 🔗 [View in SonarQube](...)

#### DAST Finding (Runtime Testing)
- **Endpoint:** `POST /`
- **Method:** POST
- 🔗 [View in StackHawk](...)

**Confidence Level:** high ✅
```

## How It Works

### 1. Data Collection

- Fetches SAST issues from SonarQube API
- Filters out imported DAST issues (e.g., `external_StackHawk:*`)
- Parses DAST findings from SARIF files

### 2. AI-Powered Correlation

Uses Claude's general-purpose agent to:
- Match vulnerability types across tools
- Trace code paths from controllers to endpoints
- Analyze taint flows (source → sink)
- Score confidence based on multiple factors

### 3. Report Generation

Creates a comprehensive markdown report with:
- Correlated findings prioritized by confidence
- Detailed taint flow analysis
- Direct links to both SonarQube and DAST tools
- Coverage gap analysis
- Actionable remediation recommendations

### 4. SonarQube Tagging (Optional)

- Tags correlated issues with `dast-detected`
- Adds detailed correlation comments
- Links to DAST findings for easy reference

## Benefits

### 🎯 Focus on What Matters

Not all SAST findings are exploitable in practice. This skill identifies the 2-5% of SAST issues that are **confirmed exploitable** by DAST testing, allowing your team to prioritize high-confidence vulnerabilities.

### 📈 Understand Tool Coverage

See which vulnerability types are covered by SAST vs. DAST:
- **SAST excels**: Code-level issues (XXE, path traversal, command injection)
- **DAST excels**: Runtime issues (security headers, CSRF, session management)
- **Both detect**: SQL injection, XSS (when correlated = highest priority)

### ⚡ Save Time

Manual correlation of 100+ SAST and 40+ DAST findings can take hours. This skill completes the analysis in minutes with detailed reasoning for each correlation.

### 🔗 Seamless Integration

Works with your existing tools:
- SonarQube for SAST
- StackHawk, ZAP, or any SARIF-compliant DAST scanner
- Direct integration with SonarQube issue tagging

## Correlation Strategies

### Vulnerability Type Matching
- Maps SonarQube security rules to DAST CWE/vulnerability IDs
- Example: `javasecurity:S3649` ↔ `sql-injection`

### Endpoint/Component Mapping
- Traces Java controller classes to HTTP endpoints
- Example: `HomeController POST "/"` ↔ `POST / ` DAST finding

### Taint Flow Analysis
- Examines data flow from request parameters to vulnerable sinks
- Example: `@RequestParam` → SQL query → matches DAST SQL injection

### Confidence Scoring
- **HIGH**: Same vuln type + exact endpoint match + taint flow alignment
- **MEDIUM**: Same vuln type + partial component match
- **LOW**: Same vuln type only

## Use Cases

- **Security Teams**: Validate SAST findings with runtime exploitation proof
- **DevSecOps**: Prioritize vulnerability remediation based on confirmed exploitability
- **Compliance**: Demonstrate comprehensive security testing coverage
- **Development Teams**: Focus on fixing vulnerabilities that matter most

## Supported Languages

The correlation logic works with any language supported by SonarQube and your DAST tool. Taint flow analysis is optimized for:
- Java (Spring Boot, Spring MVC)
- Other languages supported with basic correlation

## Troubleshooting

### No Correlations Found

If the analysis produces no correlations:
- Ensure both SAST and DAST scanned the same application
- Verify SARIF file contains actual findings (not just info-level)
- Check that SAST issues are real security findings (not code quality issues)
- The Agent may need more specific instructions (skill will auto-retry if needed)

### SonarQube API Errors

- Verify `SONAR_TOKEN` has correct permissions
- Ensure `SONARQUBE_URL` is accessible from your machine
- Check `SONAR_PROJECT_KEY` matches your project

### SARIF File Issues

- Ensure SARIF file follows the [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- Validate with: `cat your-file.sarif | jq .`

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Support for additional DAST tools
- Enhanced correlation strategies
- Improved report formatting
- Language-specific taint flow analysis

## License

[MIT License](LICENSE)

## Credits

Built with [Claude Code](https://claude.ai/code) by Anthropic.

## Support

- **Issues**: [GitHub Issues](https://github.com/mathiasconradt/sonarqube-sast-dast-correlation/issues)
- **Documentation**: See [SKILL.md](SKILL.md) for detailed implementation workflow
- **Claude Code**: [claude.ai/code](https://claude.ai/code)

---

**Made with ❤️ for the AppSec community**
