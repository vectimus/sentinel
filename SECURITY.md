# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in the Sentinel pipeline, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### How to report

1. **GitHub Security Advisories**: Use the "Report a vulnerability" button on the [Security tab](https://github.com/vectimus/sentinel/security/advisories) of this repository.
2. **Email**: Send details to security@vectimus.com.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix if you have one

## Response timeline

- **Acknowledgement**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Dependent on severity, typically within 30 days for critical issues

## Scope

The following are in scope for this repository:

- Pipeline prompt injection (causing agents to produce malicious policies)
- Sandbox bypass (policies that pass verification but don't actually work)
- Credential exposure in findings or advisory output
- Agent governance bypass (Sentinel circumventing its own Vectimus policies)

## License

Apache 2.0
