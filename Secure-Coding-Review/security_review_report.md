# Secure Coding Review Report

**CodeAlpha Cybersecurity Internship — Task 3**

**Author:** Usama  
**Python Version:** 3.14.8  
**Static Analysis Tool:** Bandit 1.9.4  
**Project Type:** Educational secure-coding review

## 1. Introduction

This project reviews an intentionally vulnerable Python login application and compares it with an improved implementation. The objective is to identify security weaknesses, recommend remediation, and validate the improvements using static analysis and automated tests.

The project is for educational purposes and is not a production authentication system.

## 2. Scope of Review

The review covers:

- SQL query construction and SQL injection risks.
- Password handling and storage.
- Login validation and failure behavior.
- Exposure of sensitive information.
- Static analysis using Bandit.
- Automated tests of the secure demonstration.

## 3. Vulnerable Application

**File:** `vulnerable_app.py`

The vulnerable demonstration intentionally uses insecure coding patterns to illustrate potential security weaknesses.

### 3.1 SQL Injection

**Finding:** SQL query construction incorporates input into a query string.

**Risk:** An attacker may manipulate the intended SQL query through crafted input.

**Recommendation:** Use parameterized SQL statements so user input is treated as data rather than executable SQL.

### 3.2 Hardcoded Demo Credentials

**Finding:** The vulnerable demonstration includes fixed example credentials.

**Risk:** Hardcoded credentials can be exposed through source code and may be reused inappropriately.

**Recommendation:** Avoid hardcoded credentials in real applications. Use an appropriate account-management and secret-handling design.

### 3.3 Password Handling

**Finding:** The vulnerable example does not use the improved salted password-hashing approach implemented in the secure demonstration.

**Risk:** Inadequate password storage can expose users if stored credentials are disclosed.

**Recommendation:** Store passwords using a suitable password-hashing function with a unique salt and appropriate work factor.

### 3.4 Sensitive Output

**Finding:** The vulnerable example prints SQL query information.

**Risk:** Logging or displaying sensitive query details can expose implementation information.

**Recommendation:** Avoid unnecessary sensitive output. Use controlled logging that does not disclose secrets.

## 4. Secure Application

**File:** `secure_app.py`

The improved demonstration addresses the principal weaknesses identified in the vulnerable example.

### 4.1 Parameterized SQL

SQL queries use placeholders and separately supplied parameters.

**Security benefit:** User-provided login input is treated as data rather than being directly inserted into SQL query syntax.

### 4.2 Password Hashing

The application uses PBKDF2-HMAC-SHA256 with a random salt and a configured iteration count of 600,000.

**Security benefit:** The application stores a derived password hash instead of the original password.

### 4.3 Login Validation

The application checks the submitted password against the stored hash and uses `hmac.compare_digest` for comparison.

**Security benefit:** Incorrect credentials are rejected, and hash comparison uses a constant-time comparison function.

### 4.4 Reduced Information Disclosure

The secure demonstration returns a generic login failure message for an unknown username or incorrect password.

**Security benefit:** It avoids revealing which of those two login conditions failed.

## 5. Recommendations

1. Use parameterized SQL queries throughout the application.
2. Never hardcode real credentials or secrets in source code.
3. Store passwords using a suitable salted password-hashing function.
4. Avoid printing passwords, secrets, or sensitive query information.
5. Use generic authentication failure messages.
6. Add appropriate rate limiting and account-protection measures before deploying a real authentication service.
7. Perform automated testing, dependency checks, and manual security reviews.

## 6. Remediation Summary

| Security area | Vulnerable approach | Improved approach |
|---|---|---|
| SQL queries | String-based query construction | Parameterized SQL |
| Password storage | Does not use the improved salted hashing approach | Salted PBKDF2-HMAC-SHA256 hash |
| Login comparison | Insecure demonstration logic | Hash verification with `hmac.compare_digest` |
| Failure messages | Insecure example behavior | Generic login failure message |
| Testing | Deliberately vulnerable demonstration | Automated tests and static analysis |

## 7. Testing Approach

Testing includes a review of the vulnerable implementation, a static-analysis comparison using Bandit, and automated tests of the secure implementation.

The automated test suite checks:

- Successful login with valid credentials.
- Rejection of an incorrect password.
- Rejection of an unknown username.
- Rejection of SQL injection input as a valid login.
- Storage of a password hash rather than the original password.

## 8. Security Testing and Validation

### Test 1: Vulnerable Login Application

**Objective:** Identify unsafe handling of login input.

**Method:** Review the source code and use controlled educational test input.

**Finding:** The original implementation constructs SQL dynamically, creating a SQL injection vulnerability.

**Result:** The issue is documented for remediation.

### Test 2: Secure Login — Valid Credentials

**Objective:** Confirm that the secure demonstration accepts the correct username and password.

**Expected result:** Login successful.

**Validation:** The automated valid-login test passed.

### Test 3: Secure Login — Incorrect Password

**Objective:** Confirm that an incorrect password is rejected.

**Expected result:** Login failed.

**Validation:** The automated incorrect-password test passed.

### Test 4: Parameterized SQL

**Objective:** Verify that SQL input cannot bypass login validation through query manipulation.

**Expected result:** User input is treated as data.

**Validation:** The source uses parameterized SQL, and the automated SQL injection input test passed.

### Test 5: Password Storage

**Objective:** Confirm that the original password is not stored directly.

**Expected result:** The database stores a salted password hash.

**Validation:** The automated password-storage test passed.

### Testing Limitations

The secure demonstration uses an in-memory database and creates a new demo account on each run. These tests cover basic educational security concepts and do not establish production readiness.

## 9. Static Analysis Results — Bandit

**Tool:** Bandit 1.9.4  
**Python version:** 3.14.8  
**Scan date:** October 23, 2026

### 9.1 Vulnerable Application Scan

**File:** `vulnerable_app.py`

- Total issues: 1
- Finding: B608 — possible SQL injection through string-based query construction
- Severity: Medium
- Confidence: Low
- Reported location: Line 25

**Analysis:** The query construction triggered a Bandit warning because SQL syntax incorporates dynamically constructed input. Parameterized queries are recommended.

### 9.2 Secure Application Scan

**File:** `secure_app.py`

- Total issues: 0
- Bandit result: No issues identified.

**Analysis:** Bandit did not identify issues in the secure version during this scan. This does not prove that the application is completely secure or that all vulnerabilities have been detected.

### 9.3 Comparison

The vulnerable version triggered a B608 warning, while the secure version uses parameterized SQL and did not trigger a finding in this scan.

### 9.4 Limitations

Static analysis is only one part of a security review. Manual source-code inspection and functional testing are also necessary.

## 10. Automated Test Results

**Testing tool:** Python `unittest`  
**Python version:** 3.14  
**Result:** PASS — all five tests passed.

| Test | Result |
|---|---|
| Valid login accepted | PASS |
| Incorrect password rejected | PASS |
| Unknown username rejected | PASS |
| SQL injection input rejected | PASS |
| Password not stored as plaintext | PASS |

**Test command:**

```powershell
py -3.14 -m unittest -v test_secure_app
```

### Conclusion

The review identified a SQL injection risk in the vulnerable demonstration and documented recommended remediation. The secure demonstration uses parameterized SQL, salted password hashing, and generic login failure messages.

Bandit reported one B608 finding in the vulnerable application and no findings in the secure application. All five automated tests passed.

These results support the educational comparison but do not establish that the application is production-ready or free from all vulnerabilities.

## Responsible Use

This project is intended for authorized educational testing and secure-coding practice. Do not deploy the intentionally vulnerable application or test systems without appropriate authorization.
