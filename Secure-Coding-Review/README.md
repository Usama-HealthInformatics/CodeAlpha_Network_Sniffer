# Secure Coding Review

**CodeAlpha Cybersecurity Internship — Task 3**

**Author:** Usama  
**Project:** Secure Coding Review  
**Language:** Python

## 1. Overview

This project demonstrates a secure coding review by comparing an intentionally vulnerable Python login application with an improved implementation.

The project identifies common security weaknesses, explains remediation techniques, and validates the improvements through static analysis and automated testing.

This is an educational project and is not a production authentication system.

## 2. Objectives

- Identify SQL injection risks.
- Review password handling and storage.
- Compare vulnerable and secure coding practices.
- Use Bandit for Python static analysis.
- Test authentication behavior with automated unit tests.
- Document findings and security recommendations.

## 3. Project Files

| File | Description |
|---|---|
| `vulnerable_app.py` | Demonstrates intentionally insecure login practices. |
| `secure_app.py` | Demonstrates improved login security practices. |
| `test_secure_app.py` | Contains automated tests for the secure application. |
| `security_review_report.md` | Documents findings, recommendations, and test results. |
| `bandit_vulnerable_report.txt` | Static analysis report for the vulnerable application. |
| `bandit_secure_report.txt` | Static analysis report for the secure application. |

## 4. Security Issues Reviewed

### SQL Injection

The vulnerable example constructs SQL queries using input within a query string.

**Remediation:** Use parameterized SQL queries to treat user input as data.

### Password Storage

The vulnerable example does not implement the improved salted password-hashing approach used in the secure version.

**Remediation:** Use an appropriate password-hashing function with a unique salt and suitable work factor.

### Hardcoded Credentials

The vulnerable demonstration includes fixed example credentials.

**Remediation:** Do not hardcode real credentials or secrets in application source code.

### Information Disclosure

The vulnerable example displays SQL query information.

**Remediation:** Avoid exposing sensitive implementation details and secrets.

## 5. Security Improvements

The secure demonstration includes:

- Parameterized SQL queries.
- PBKDF2-HMAC-SHA256 password hashing.
- Random salts for password hashes.
- A configured hashing iteration count of 600,000.
- Password verification using `hmac.compare_digest`.
- Generic login failure messages.
- Automated tests for important authentication behaviors.

## 6. Testing and Validation

The project uses Python's `unittest` framework and Bandit static analysis.

The five automated tests cover:

1. Successful login with valid credentials.
2. Rejection of an incorrect password.
3. Rejection of an unknown username.
4. Rejection of SQL injection input as valid login credentials.
5. Verification that the original password is not stored as plaintext.

### Run the Tests

From the `Secure-Coding-Review` directory, run:

```powershell
py -3.14 -m unittest -v test_secure_app
```

**Recorded result:** All five automated tests passed.

### Run Static Analysis

Analyze the vulnerable application:

```powershell
py -3.14 -m bandit .\vulnerable_app.py
```

Analyze the secure application:

```powershell
py -3.14 -m bandit .\secure_app.py
```

**Recorded results from October 23, 2026:**

- Vulnerable application: one B608 finding related to possible SQL injection.
- Secure application: no issues identified by Bandit in that scan.

Static analysis cannot guarantee that an application is free of vulnerabilities.

## 7. Tools and Technologies

- Python 3.14
- Bandit 1.9.4
- SQLite
- Python `unittest`
- Git and GitHub

## 8. Learning Outcomes

This project demonstrates practical experience with:

- Identifying insecure coding patterns.
- Understanding SQL injection risks.
- Improving password storage practices.
- Writing automated security tests.
- Running static analysis tools.
- Documenting findings and remediation recommendations.

## 9. Responsible Use

The vulnerable application is provided solely for authorized educational testing and secure-coding practice. Do not deploy it as a real authentication service or test systems without appropriate authorization.

## 10. Author

**Usama**  
Cybersecurity learner interested in network security, SOC operations, and defensive security.

GitHub profile: https://github.com/Usama-HealthInformatics

## Conclusion

This project compares vulnerable and improved authentication code, documents security recommendations, and uses automated tests and static analysis to evaluate the improvements. It is a learning demonstration and does not establish production readiness.

