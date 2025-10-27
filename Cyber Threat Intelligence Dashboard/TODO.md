# TODO: Fix Vulnerability Scanner Detection

## Completed Tasks
- [x] Update scan_local_vulnerabilities function in app.py to scan from the app's base directory and simplify detection logic for better coverage of sample files.
- [x] Add a test endpoint /test/threats to verify detection without login.
- [x] Run the Flask app and verify that the sample vulnerabilities are detected in the /test/threats endpoint.

## Verification Results
- [x] SQL Injection detected in sql_injection_sample.py and sample_vuln.py.
- [x] XSS detected in xss_sample.html.
- [x] Phishing detected in phishing_email.txt.
- [x] Malware detected in malware_sample.exe.
- [x] Additional detections in app.py and templates (expected as they contain scripts and secrets).

## Pending Tasks
- [x] Remove the test endpoint /test/threats after verification.
- [ ] Optionally, refine detection to exclude app files if not intended.
