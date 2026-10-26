import {Effect} from "effect";

import type {Principal} from "../core/identity.js";
import {AuthorizationService} from "./authorization.js";
import {InstallationAccessService} from "./installation-access.js";

/**
 * List the copied directory groups. Anyone who may list artifacts may see
 * group names, so a project can be shared with a group by someone who is not
 * an administrator.
 */
export const listDirectoryGroups = Effect.fn("listDirectoryGroups")(function*(
  principal: Principal,
) {
  yield* AuthorizationService.use((authorization) =>
    authorization.requireArtifactListing(principal)
  );
  return yield* InstallationAccessService.use((access) => access.listDirectoryGroups());
});
