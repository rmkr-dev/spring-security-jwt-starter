# Security policy

This starter sits in the authentication path of the services that use it, so security reports are
taken seriously and handled ahead of other work.

## Supported versions

Only the latest minor release line gets security fixes. Before 1.0, fixes are not backported to
older minor versions; upgrade to the latest release to pick them up.

| Version | Supported |
| ------- | --------- |
| latest 0.x minor | Yes |
| older 0.x minors | No |

## Reporting a vulnerability

Please do **not** open a public issue, pull request or discussion for a suspected vulnerability.

Report it privately through GitHub's
[security advisory form](https://github.com/rmkr-dev/spring-security-jwt-starter/security/advisories/new).
Include as much of the following as you can:

- the affected version or commit,
- the configuration involved (redact tenant ids, client ids and secrets),
- what an attacker can do, and the steps or a test that reproduce it.

You can expect an acknowledgement within 5 working days and an assessment within 10. If the report
is confirmed, a fix is prepared in a private fork, released, and published as a GitHub security
advisory that credits you, unless you prefer not to be named.

## Scope

In scope: anything in this repository that could let a token be accepted when it should not be
(signature, issuer, audience, tenant, expiry or token-type checks), that grants authorities a caller
should not have, that leaks tokens, secrets or keys (in logs, errors or metrics), or that weakens the
outbound credential handling.

Out of scope: vulnerabilities in Spring, Nimbus, the Azure SDK or other dependencies (report those
upstream; we will pick up the fixed version), and the sample applications, which are not meant to be
deployed as they are.
