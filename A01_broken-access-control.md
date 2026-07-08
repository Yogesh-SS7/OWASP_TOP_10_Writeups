# A01: Broken Access Control — Client-Side Privilege Escalation

## Executive Summary

An access-control weakness was identified in an intentionally vulnerable web application within an authorised training environment. A standard authenticated user was able to reach administrative functionality by modifying a client-controlled value used during the post-login redirect flow.

The application exposed an authorization-related value in its response and used that value to determine where the user should be redirected. By changing the value associated with administrative access, the standard user was redirected to an administrative endpoint that should have been restricted.

Once the administrative area was accessible, the account-management interface allowed the low-privileged user to grant administrator privileges to their own account. This demonstrated both an authorization bypass and vertical privilege escalation.

## Scope

| Item             | Details                                                       |
| ---------------- | ------------------------------------------------------------- |
| Target           | Intentionally vulnerable web application                      |
| Environment      | Authorised isolated security training lab                     |
| Test account     | Newly created standard user account                           |
| Testing approach | Manual request and response analysis using Burp Suite         |
| Out of scope     | Production systems, external targets, and destructive testing |

## OWASP Classification

**OWASP Top 10: A01 — Broken Access Control**

Broken Access Control occurs when an application does not correctly enforce which users are permitted to access specific resources or perform specific actions.

This assessment identified **vertical privilege escalation**, where a standard user gained access to administrator-only functionality.

## Objective

The objective was to determine whether a standard authenticated user could bypass role restrictions and access administrative functionality by manipulating data sent between the browser and the server.

## Application Reconnaissance

The application exposed the following primary functions:

* User registration
* User login
* Standard user dashboard
* Administrative dashboard
* User-management functionality

A standard account was created to establish a low-privilege baseline. After authentication, HTTP traffic was captured and reviewed to understand how the application handled session state, user identity, and post-login navigation.

## Technical Analysis

Following successful login, the application returned a JSON response containing user-related information and a redirect value. The redirect value included an authorization-related parameter that influenced the destination page shown to the user.

The application treated this browser-visible value as meaningful for access decisions.

A simplified representation of the observed redirect behaviour is shown below:

```text
dashboard.php?isadmin=false
```

The value was changed to:

```text
dashboard.php?isadmin=true
```

After modifying the parameter, the application redirected the standard user to an administrative page that was normally hidden from non-administrative users.

This indicates that the application relied on client-controlled data rather than performing a reliable server-side authorization check before allowing access to the administrative endpoint.

## Proof of Concept

1. Register and authenticate with a standard user account.
2. Capture the post-login HTTP response using Burp Suite.
3. Identify the redirect value containing the authorization-related parameter.
4. Copy the redirect path into the browser address bar.
5. Change the administrative parameter from `false` to `true`.
6. Request the modified URL.
7. Observe that the application exposes the administrative dashboard to the standard user.
8. Use the administrative account-management interface to enable administrator access for the standard account.
9. Confirm that the account now has administrator privileges.

## Result

The application allowed a standard user to access an administrative interface by altering a client-controlled parameter.

The administrative interface also allowed the user to change account privilege settings. As a result, the standard account could be elevated to administrator level.

**Finding status: Confirmed**

## Impact

An attacker with a valid low-privileged account could potentially:

* Access administrator-only pages
* Modify user privilege settings
* Promote their own account to administrator
* Remove or alter other users’ administrative access
* Access sensitive user-management features
* Compromise the confidentiality and integrity of application data

The risk is high because a low-privileged authenticated user can obtain administrative control without legitimate authorization.

## Root Cause

The root cause was the use of client-controlled data in authorization logic.

Values delivered to or stored in the browser—including URL parameters, JSON fields, hidden form inputs, cookies, and JavaScript variables—must be considered untrusted. A user can modify them before sending a request or before navigating to a page.

The application failed to independently verify, on the server, whether the authenticated user had permission to access the administrative endpoint and perform account-management actions.

## Remediation

The application should implement server-side authorization controls for every sensitive endpoint and action.

Recommended fixes:

* Determine the authenticated user’s role from a trusted server-side session or database record.
* Do not use URL parameters, browser-side JSON values, hidden fields, or cookies as the source of truth for authorization.
* Enforce an explicit administrator-role check before serving administrative pages.
* Enforce authorization again before every sensitive action, including role changes and account updates.
* Apply deny-by-default rules: users should receive access only when the server confirms the required permission.
* Return `403 Forbidden` when a standard user requests an administrator-only resource.
* Prevent users from modifying their own role or privilege level unless an authorised administrator performs that action.
* Log denied authorization attempts and unexpected role-change requests.
* Add automated tests verifying that a standard user cannot access administrative routes, even if request parameters are modified.

## Secure Design Example

A secure implementation should ignore client-provided role values and verify the role stored on the server.

```php
session_start();

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    exit('Authentication required');
}

$userId = $_SESSION['user_id'];
$userRole = getUserRoleFromDatabase($userId);

if ($userRole !== 'admin') {
    http_response_code(403);
    exit('Access denied');
}

// Administrative functionality continues here.
```

## Evidence

1. Standard account registration or login.
![here is the first view of the landing page](/images/A01-evidence/Login-page.png)
(/images/A01-evidence/Post-register.png)
2. Burp Suite response the post-login redirect value.
![Here is the response from the burp suite](/images/A01-evidence/intial_Request.png)
3. The original redirect path with the non-administrator value.
4. The modified redirect path with the administrator value.
5. Successful access to the administrative dashboard.
6. The account-management page showing the privilege change

## Key Lessons

* Authentication identifies the user; authorization determines what that user is allowed to do.
* The browser is not trusted.
* A hidden administrative page is not protected unless the server blocks unauthorised requests.
* Authorization must be checked server-side for every protected route and action.
* Privilege changes are high-risk operations and require strict permission checks.
* This vulnerability is a clear example of vertical privilege escalation under OWASP A01: Broken Access Control.
