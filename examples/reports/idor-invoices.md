# IDOR in /api/v2/invoices/{id} exposes other customers' invoices

## Summary
The invoices API authorizes the request only by checking that the caller is logged in, not that the invoice belongs to the caller. Any authenticated user can read any other customer's invoice, including name, billing address and the last four digits of the payment card, by changing the numeric invoice ID.

**Asset:** https://app.example.com/api/v2/invoices/{id}  
**Weakness:** Insecure Direct Object Reference (CWE-639)  
**Severity:** Medium - CVSS 6.5  
**CVSS vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

## Steps to Reproduce
1. Create two free accounts: attacker@example.org (account A) and victim@example.org (account B).
2. As account B, create an invoice and note its ID from the URL, e.g. `1043`.
3. Log in as account A and copy your session cookie.
4. Send `GET /api/v2/invoices/1043` with account A's session cookie.
5. Observe `200 OK` with account B's full invoice JSON (name, address, card last4).
6. Repeat with sequential IDs (1040-1045) to confirm the IDs are enumerable.

## Impact
Any registered user can read the billing details of every customer by enumerating sequential invoice IDs. This exposes personal data (name, address) and partial payment data, with GDPR implications, and requires no special privileges beyond a free account.

## Remediation
Enforce object-level authorization: verify the invoice's owner matches the authenticated user (or the caller's organization) on every read. Consider non-sequential identifiers as defense in depth.

## References
- https://cwe.mitre.org/data/definitions/639.html
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/

<!-- Formatted with bounty-pilot. Findings must be manually verified before submission. -->
