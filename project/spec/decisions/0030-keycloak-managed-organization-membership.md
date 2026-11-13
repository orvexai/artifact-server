# 0030: Keycloak-managed organization membership

**Status:** Accepted
**Date:** November 13, 2026

## Decision

For organization-scoped Artifact Server installations, Keycloak is the source
of truth for organization membership. Artifact Server does not manually admit
organization members and does not write membership to Keycloak. Organization
owners manage membership in the identity provider; Artifact Server reads the
verified organization claim and applies the organization's admission policy.

The tenant Members settings page therefore omits the manual “Admit member”
control and explains that membership is managed by the identity provider. The
tenant `POST /api/v1/members` endpoint returns a generic conflict stating that
members are managed by the identity provider for every attempted address. It
does not distinguish an existing staff member from an address that cannot be
admitted, so the endpoint does not become a membership oracle.

Standalone installations retain their existing manual admission workflow.
