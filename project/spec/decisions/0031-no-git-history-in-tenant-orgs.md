# 0031: Git history is unavailable in tenant organizations

**Status:** Accepted
**Date:** November 13, 2026

## Decision

Git history remains unavailable in non-Orvex organizations. The configured
provider owns one Orvex installation location, and tenant organizations cannot
claim or reuse that provider identity. Enabling tenant Git history requires a
provider that supports a separate namespace for each organization.

The Git history serializer omits publisher principal IDs for tenant metadata,
including if tenant Git history is enabled in a future implementation.
