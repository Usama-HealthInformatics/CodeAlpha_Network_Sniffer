\## 8. Security Testing and Validation



\### Test 1: Vulnerable Login Application



\*\*Objective:\*\* Check whether the original application safely handles login input.



\*\*Test method:\*\* Conducted local testing using dummy credentials and controlled SQL injection input.



\*\*Expected secure behavior:\*\* Invalid credentials must be rejected, and user input must not alter the intended SQL query.



\*\*Result:\*\* The original implementation uses dynamically constructed SQL. This creates a SQL injection vulnerability that requires remediation.



\### Test 2: Secure Login — Valid Credentials



\*\*Objective:\*\* Confirm that the secure demonstration accepts the correct username and password.



\*\*Expected result:\*\* Login successful.



\*\*Actual result:\*\* Record the result after completing the valid-credentials test.



\### Test 3: Secure Login — Incorrect Password



\*\*Objective:\*\* Confirm that the secure demonstration rejects an incorrect password.



\*\*Expected result:\*\* Login failed.



\*\*Actual result:\*\* Record the result after completing the incorrect-password test.



\### Test 4: Parameterized SQL



\*\*Objective:\*\* Verify that login queries use parameterized SQL statements.



\*\*Expected result:\*\* User input is treated as data rather than executable SQL.



\*\*Status:\*\* Verified by source-code inspection; additional automated tests are recommended.



\### Test 5: Password Storage



\*\*Objective:\*\* Verify that passwords are not stored directly in the database.



\*\*Expected result:\*\* The demonstration stores a salted PBKDF2 password hash rather than the original password.



\*\*Status:\*\* Verified by source-code inspection.



\### Testing Limitations



The secure application uses an in-memory database and creates a new demo account on each run. These tests demonstrate basic secure-coding concepts and do not establish production readiness. Further automated testing, dependency checks, and independent review would be required for a production application.



\## 9. Static Analysis Results — Bandit



\*\*Tool:\*\* Bandit 1.9.4  

\*\*Python version:\*\* 3.14.8  

\*\*Scan date:\*\* October 23, 2026



\### Vulnerable Application Scan



\*\*File:\*\* `vulnerable\_app.py`



\- Total issues: 1

\- Finding: B608 — possible SQL injection through string-based query construction

\- Severity reported by Bandit: Medium

\- Confidence reported by Bandit: Low

\- Location: Line 25



\*\*Analysis:\*\* The SQL query incorporates user-controlled values directly into a query string. Parameterized queries should be used to prevent user input from changing SQL query logic.



\### Secure Application Scan



\*\*File:\*\* `secure\_app.py`



\- Total issues: 0

\- Bandit result: No issues identified



\*\*Analysis:\*\* Bandit did not identify any issues in the secure version during this scan. This result does not guarantee that the application is completely secure or that every vulnerability has been detected.



\### Comparison



The vulnerable version triggered a Bandit SQL query construction warning. The secure version uses parameterized SQL statements and did not trigger a finding in this scan.



\### Limitations



Static analysis is only one part of a security review. Manual inspection and functional tests are also necessary. Login testing must confirm that valid credentials succeed and incorrect credentials fail before those results can be marked as verified.





\## 10. Automated Test Results



\*\*Testing tool:\*\* Python `unittest`  

\*\*Python version:\*\* 3.14  

\*\*Result:\*\* PASS — all 5 tests passed.



| Test | Result |

|---|---|

| Valid login accepted | PASS |

| Incorrect password rejected | PASS |

| Unknown username rejected | PASS |

| SQL injection input rejected | PASS |

| Password not stored as plaintext | PASS |



\*\*Test command:\*\*

```powershell

py -3.14 -m unittest -v test\_secure\_app

```



\*\*Conclusion:\*\* The tests confirm that the secure demonstration accepts valid credentials, rejects invalid login attempts, uses parameterized SQL queries, and stores a salted password hash rather than the original password.



\*\*Limitations:\*\* These are basic automated tests of an educational application. They do not establish that the application is production-ready or free of all security vulnerabilities.



