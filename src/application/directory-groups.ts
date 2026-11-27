import {Effect} from "effect";

import type {Principal} from "../core/identity.js";
import {AuthorizationService} from "./authorization.js";
import {InstallationAccessService} from "./installation-access.js";

/**
 * Members and above may see groups for the project sharing picker. Guests and
 * viewers never enumerate groups; viewers can still share by full path.
 */
export const listDirectoryGroups = Effect.fn("listDirectoryGroups")(function*(
  principal: Principal,
) {
  if (principal.kind === "human" &&
    (principal.membershipRole === "guest" || principal.membershipRole === "viewer")) return [];
  yield* AuthorizationService.use((authorization) =>
    authorization.requireArtifactListing(principal)
  );
  return yield* InstallationAccessService.use((access) =>
    access.directoryGroupScope().kind === "none" ? Effect.succeed([]) : access.listDirectoryGroups()
  );
});
