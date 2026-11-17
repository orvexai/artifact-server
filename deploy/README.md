# Artifact Server on Manchester

`deploy/orvex/production` is the production GitOps root. The production HTTPRoutes match the
configured hostnames, but DNS remains on today's cluster until the move; verify production with the
host header supplied by Bring-up through the Manchester gateway. There are no ExternalDNS records
in the production render.

`deploy/orvex/rehearsal` is a separate, empty environment with no hostnames or HTTPRoutes. Reach it
only with `kubectl -n artifact-server-rehearsal port-forward svc/artifact-server 8787:80` after the
rehearsal restore scrub and the required rehearsal guards are in place. Delete it at cutover.

Before stage 1, production uses today's Keycloak issuer and directory address. The application
network policy's two `/32:443` entries are pending Overlay 2's schema PR. They document the two
Cloudflare-fronted addresses already reachable under D107; they do not restrict egress or add
reachability. D107 allows every app namespace to reach the public internet (`0.0.0.0/0` and `::/0`,
except private, link-local, node, pod, service and LB-pool ranges) until the egress gateway.
