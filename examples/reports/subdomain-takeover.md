# Subdomain takeover of status-old.example.com via unclaimed object-storage bucket

**Target:** status-old.example.com  
**Vulnerability type:** Subdomain Takeover (CWE-1394)  
**Suggested priority / severity:** Medium

## Description
status-old.example.com has a CNAME pointing to a cloud storage website endpoint whose bucket no longer exists. Anyone can register the bucket name and serve arbitrary content from the example.com domain.

## Steps to reproduce
1. Run `dig CNAME status-old.example.com` and note it points to `example-status.storage.example.net`.
2. Request `https://status-old.example.com/` and observe the provider's 'NoSuchBucket' error page.
3. Register a bucket named `example-status` in the provider console (only a harmless `poc.txt` containing the researcher's handle was uploaded).
4. Request `https://status-old.example.com/poc.txt` and observe the uploaded content served from the example.com hostname.
5. The test file was removed and the bucket released after verification.

## Impact
An attacker could host phishing pages or malicious scripts on a trusted example.com subdomain, and could set cookies scoped to `.example.com` if the cookie policy allows it.

## Recommended fix
Remove the dangling DNS record, or recreate and lock down the bucket. Audit DNS regularly for CNAMEs pointing at deprovisioned resources.

## Supporting material
- https://owasp.org/www-project-web-security-testing-guide/

<!-- Formatted with bounty-pilot. Findings must be manually verified before submission. -->
