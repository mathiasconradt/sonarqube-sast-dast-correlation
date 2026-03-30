# Contributing to SonarQube SAST-DAST Correlation

Thank you for considering contributing to this project! This skill helps security teams and developers correlate SAST and DAST findings to prioritize vulnerability remediation.

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- **Description**: Clear description of the issue
- **Steps to Reproduce**: Detailed steps to reproduce the behavior
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Environment**:
  - Claude Code version
  - SonarQube version
  - DAST tool and version (StackHawk, ZAP, etc.)
  - Operating system
- **Logs/Screenshots**: Any relevant error messages or screenshots

### Suggesting Enhancements

We welcome suggestions for new features! Please open an issue with:
- **Use Case**: Describe the problem you're trying to solve
- **Proposed Solution**: Your suggested implementation
- **Alternatives**: Any alternative solutions you've considered
- **Additional Context**: Screenshots, examples, or mockups

### Pull Requests

1. **Fork the repository** and create your branch from `main`:
   ```bash
   git checkout -b feature/amazing-feature
   ```

2. **Make your changes**:
   - Follow the existing code style
   - Update documentation if needed
   - Add examples if applicable

3. **Test your changes**:
   - Test with SonarQube and at least one DAST tool
   - Verify the skill works end-to-end
   - Test with different project configurations

4. **Commit your changes**:
   ```bash
   git commit -m "Add amazing feature"
   ```
   - Use clear, descriptive commit messages
   - Reference issue numbers if applicable

5. **Push to your fork**:
   ```bash
   git push origin feature/amazing-feature
   ```

6. **Open a Pull Request**:
   - Provide a clear description of the changes
   - Link to related issues
   - Include screenshots or examples if relevant

## Development Setup

### Prerequisites

- Claude Code (CLI, Desktop, or Web)
- Access to a SonarQube instance
- DAST scan results (StackHawk, ZAP, etc.)

### Local Development

1. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/sonarqube-sast-dast-correlation.git
   cd sonarqube-sast-dast-correlation
   ```

2. Install in Claude Code skills directory:
   ```bash
   # Create symlink for easier development
   ln -s $(pwd) ~/.claude/skills/sonarqube-sast-dast-correlation
   ```

3. Test your changes:
   ```bash
   # In Claude Code, run:
   /sonarqube-sast-dast-correlation
   ```

### Project Structure

```
sonarqube-sast-dast-correlation/
├── SKILL.md              # Skill implementation (main logic)
├── README.md             # User documentation
├── CONTRIBUTING.md       # This file
├── LICENSE               # MIT License
├── .gitignore           # Git ignore rules
└── examples/            # Example reports and data
    ├── sonarqube-stackhawk-example/
    │   ├── sast-dast-correlation-report.md
    │   ├── correlations.json
    │   └── README.md
    └── sonarqube-zap-example/
        └── ...
```

## Areas for Contribution

### High Priority

- **Additional DAST Tool Support**: Add correlation strategies for other SARIF-compliant tools
- **Language-Specific Taint Flow**: Improve taint flow analysis for Python, JavaScript, C#, etc.
- **Report Templates**: Add customizable report templates or export formats (PDF, HTML, CSV)
- **CI/CD Integration**: Add examples for GitHub Actions, GitLab CI, Jenkins

### Medium Priority

- **Performance Optimization**: Optimize correlation for large codebases (1000+ issues)
- **Advanced Filtering**: Add filters for severity, file paths, issue types
- **Historical Tracking**: Track correlation trends over time
- **Custom Rules**: Allow users to define custom correlation rules

### Good First Issues

- **Documentation**: Improve examples, add troubleshooting tips
- **Error Messages**: Make error messages more helpful
- **Examples**: Add more example reports for different tool combinations
- **Tests**: Add validation tests for SARIF parsing

## Coding Guidelines

### SKILL.md Format

- Follow the existing YAML frontmatter format
- Use clear section headers (###)
- Include code examples in triple backticks
- Document all configuration options
- Explain error handling

### Correlation Logic

When adding new correlation strategies:

1. **Document the strategy** in SKILL.md
2. **Explain the confidence scoring** (why HIGH vs MEDIUM vs LOW)
3. **Provide examples** of matching SAST and DAST rules
4. **Test with real data** from multiple projects

### Report Generation

When modifying reports:

- Maintain markdown formatting consistency
- Keep executive summary concise (< 1 page)
- Ensure all links are valid and clickable
- Use emojis sparingly and consistently
- Test rendering in common markdown viewers

## Testing Checklist

Before submitting a PR, verify:

- [ ] Skill runs successfully from start to finish
- [ ] Report is generated correctly
- [ ] All links in the report work
- [ ] SonarQube tagging works (if enabled)
- [ ] Error messages are clear and helpful
- [ ] Documentation is updated
- [ ] Examples are provided (if adding features)
- [ ] Works with at least one DAST tool (StackHawk or ZAP)

## Code of Conduct

### Our Pledge

We pledge to make participation in this project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to a positive environment:
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

Examples of unacceptable behavior:
- Trolling, insulting/derogatory comments, and personal attacks
- Public or private harassment
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by opening an issue or contacting the project maintainers. All complaints will be reviewed and investigated promptly and fairly.

## Questions?

Feel free to:
- Open an issue for questions
- Start a discussion in GitHub Discussions (if enabled)
- Reach out to maintainers

## Recognition

Contributors will be recognized in:
- GitHub contributors list
- Release notes (for significant contributions)
- Project README (for major features)

Thank you for helping make security testing more effective! 🎉
