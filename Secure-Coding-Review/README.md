
# Secure Coding Review

**CodeAlpha Cybersecurity Internship — Task 3**

## Overview

This project demonstrates a secure coding review by comparing an intentionally vulnerable Python login application with an improved version. It identifies common security weaknesses, documents recommended fixes, and uses automated tests and Bandit static analysis to evaluate the improvements.

## Project Objectives

- Identify SQL injection vulnerabilities.
- Demonstrate secure SQL query parameterization.
- Improve password storage using salted PBKDF2-HMAC-SHA256 hashes.
- Avoid hardcoded demo credentials in the secure implementation.
- Reduce unnecessary exposure of sensitive information.
- Validate security improvements using automated tests.

## Project Files

| File | Description |
|---|---|
| `vulnerable_app.py` | Educational example containing intentional security weaknesses |
| `secure_app.py` | Improved login demonstration |
| `test_secure_app.py` | Five automated security and login tests |
| `security_review_report.md` | Security findings, recommendations, and test results |
| `bandit_vulnerable_report.txt` | Bandit scan report for the vulnerable application |
| `bandit_secure_report.txt` | Bandit scan report for the secure application |

## Requirements

- Python 3.14
- Bandit 1.9.4 for static analysis
- Python standard-library modules for the application and tests

## How to Run

Open PowerShell in the `Secure-Coding-Review` project folder.

### Run the Vulnerable Demonstration

```powershell
py -3.14 vulnerable_app.py
```

This file intentionally demonstrates insecure coding patterns. Use it only for educational review.

### Run the Secure Demonstration

```powershell
py -3.14 secure_app.py
```

Create a demo account, then enter the same username and password at the login prompts to test a successful login.

### Run Automated Tests

```powershell
py -3.14 -m unittest -v test_secure_app
```

All five automated tests passed during testing.

## Static Analysis

Bandit was used to scan both applications.

- **Vulnerable application:** One B608 finding for a possible SQL injection vector; Medium severity and Low confidence.
- **Secure application:** No issues identified by Bandit.

Static analysis has limitations. A clean scan does not guarantee that an application is free of vulnerabilities.

## Automated Test Results

All five automated tests passed:

1. Valid login accepted.
2. Incorrect password rejected.
3. Unknown username rejected.
4. SQL injection input rejected.
5. Password not stored as plaintext.

## Security Improvements

The secure demonstration uses:

- Parameterized SQL queries.
- Random salts and PBKDF2-HMAC-SHA256 password hashing.
- Constant-time hash comparison with `hmac.compare_digest`.
- Generic login failure messages.
- An in-memory SQLite database for demonstration purposes.

## Limitations

This is an educational project, not a production authentication system. It does not implement account lockout, rate limiting, persistent user storage, password-reset workflows, or a complete production security review.

## Responsible Use

The vulnerable application is provided solely for authorized education and testing. Do not use its insecure techniques in real applications or test systems without permission.

## Author

Usama — Cybersecurity learner interested in network security, SOC operations, and defensive security.

GitHub: [Usama-HealthInformatics](https://github.com/Usama-HealthInformatics)



