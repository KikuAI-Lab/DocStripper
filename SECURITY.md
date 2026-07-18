# Security policy

## Supported versions

Security fixes are applied to the latest revision on the default branch. Older
commits, tags, packages, and copied browser deployments are not guaranteed to
receive backports.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting flow from this repository's
**Security** tab when it is available. Otherwise email
[hi@kikuai.dev](mailto:hi@kikuai.dev) with the subject
`[SECURITY] DocStripper`.

Include, when possible:

- the affected component, version, or commit;
- a minimal safe reproduction;
- the expected security impact;
- relevant logs or screenshots with secrets and personal data removed;
- a remediation idea, if one has been tested.

Please allow time for validation and a coordinated fix before publishing
details.

## Scope

DocStripper is designed to process documents locally. Reports about unsafe file
handling, path access, dependency compromise, unintended network disclosure,
or browser and CLI data-boundary failures are welcome. Do not submit real
confidential documents as test material.
