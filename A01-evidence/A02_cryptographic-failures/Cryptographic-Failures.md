# A02 – Cryptographic Failures

## Overview

OWASP A02 – Cryptographic Failures focuses on the incorrect implementation or misuse of cryptographic mechanisms that protect sensitive information. While strong cryptographic algorithms may be used, improper implementation can still introduce vulnerabilities that compromise authentication, confidentiality, or integrity.

During the white-box security assessment of the Campus Compass application, one cryptographic implementation issue was identified.

---

# Finding: Timing Attack on Authentication Token Comparison

**Severity:** Medium

**Status:** True Positive

**Affected File:**
```
backend/mcp-control/server.mjs
```

---

## Description

The MCP control server authenticates incoming requests using a secret authentication token stored in the environment variable:

```javascript
process.env.MCP_AUTH_TOKEN
```

However, the supplied token is verified using a normal string comparison:

```javascript
if (token !== AUTH_TOKEN) {
    return res.status(401).send("Unauthorized");
}
```

Although the authentication secret is securely stored outside the source code, using JavaScript's standard equality comparison leaks timing information during the comparison process.

---

## Why is this vulnerable?

Normal string comparison stops as soon as the first mismatching character is found.

For example:

```
Expected:
SuperSecretToken123

Attacker Guess:
SuperSecretTokenXYZ
```

The comparison will successfully match the first eleven characters before failing.

This means:

- incorrect first character → comparison returns almost immediately
- correct prefix → comparison takes slightly longer
- longer correct prefix → slightly longer execution time

An attacker capable of making many requests and measuring response times may gradually discover the authentication token one character at a time.

This type of side-channel attack is known as a **Timing Attack (CWE-208)**.

---

## Potential Impact

If successfully exploited, an attacker could:

- Recover the MCP authentication token
- Gain unauthorized access to MCP administrative endpoints
- Execute privileged operations exposed by the service
- Completely bypass authentication protecting the MCP interface

Although exploiting timing attacks over the Internet is difficult due to network latency, they become significantly more practical when:

- the service is deployed on a local network,
- hosted within cloud infrastructure,
- accessible through low-latency internal networks, or
- an attacker can issue a very large number of requests.

---

## OWASP Classification

- **A02:2021 – Cryptographic Failures**

Reason:

Although no encryption algorithm is broken, the application incorrectly performs secret comparison instead of using a constant-time comparison function, resulting in leakage of sensitive authentication information.

---

## Proof of Concept

Current implementation:

```javascript
if (token !== AUTH_TOKEN) {
    return res.status(401).send("Unauthorized");
}
```

Secure implementation:

```javascript
import crypto from "crypto";

const provided = Buffer.from(token || "", "utf8");
const expected = Buffer.from(AUTH_TOKEN, "utf8");

const valid =
    provided.length === expected.length &&
    crypto.timingSafeEqual(provided, expected);

if (!valid) {
    return res.status(401).send("Unauthorized");
}
```

The `crypto.timingSafeEqual()` function performs a constant-time comparison, preventing attackers from inferring information about the secret based on execution time.

---

## Remediation

- Replace all direct secret comparisons (`===` or `!==`) with `crypto.timingSafeEqual()`.
- Continue storing authentication secrets in environment variables.
- Apply constant-time comparisons wherever API keys, authentication tokens, HMACs, or cryptographic secrets are verified.

---

## References

- OWASP Top 10 2021 – A02: Cryptographic Failures
- CWE-208 – Observable Timing Discrepancy
- Node.js Documentation – `crypto.timingSafeEqual()`

---

## Conclusion

The Campus Compass application securely stores its authentication token outside the source code; however, the verification mechanism introduces a timing side-channel by using standard string comparison. Replacing the comparison with `crypto.timingSafeEqual()` eliminates this information leak and aligns the implementation with secure cryptographic best practices.