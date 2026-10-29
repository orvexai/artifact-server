import {Context, DateTime, Effect, Layer, Redacted} from "effect";

import {AuthorizationService} from "./authorization.js";
import {InstallationAccessService} from "./installation-access.js";
import {ProjectManagementService, type ProjectManagementFailure} from "./project-management.js";
import type {ApplicationClock} from "./application-clock.js";
import type {ContentSecretProvider} from "./content-access.js";
import {ArtifactNotFound, AuthorizationDenied, GuestRateLimitExceeded, type ArtifactRepositoryFailure, type IdentityRepositoryFailure, type ProjectArchived, type ProjectNotFound} from "../core/errors.js";
import type {Principal} from "../core/identity.js";
import type {GuestReviewInvitation, GuestReviewSession} from "../core/model.js";
import type {IdGenerator} from "../core/ports.js";

const guestIdleLifetimeMilliseconds = 24 * 60 * 60 * 1_000;
const guestSessionLifetimeMilliseconds = 7 * 24 * 60 * 60 * 1_000;

/** Identity carried by requests after the guest cookie has been verified. */
export interface GuestReviewer {
  readonly artifactId: string;
  readonly displayName: string;
  readonly guestId: string;
  readonly invitationCreatorPrincipalId: string;
  readonly projectId: string;
}

export interface GuestReviewDependencies {
  readonly clock: ApplicationClock;
  readonly ids: IdGenerator;
  readonly repository: {
    readonly createGuestInvitation: (invitation: GuestReviewInvitation) => Effect.Effect<void, ArtifactRepositoryFailure>;
    readonly findGuestInvitation: (projectId: string, artifactId: string) => Effect.Effect<GuestReviewInvitation | null, ArtifactRepositoryFailure>;
    readonly findGuestInvitationByDigest: (tokenDigest: string) => Effect.Effect<GuestReviewInvitation | null, ArtifactRepositoryFailure>;
    readonly revokeGuestInvitation: (projectId: string, artifactId: string, revokedAt: string) => Effect.Effect<boolean, ArtifactRepositoryFailure>;
    readonly createGuestSession: (session: GuestReviewSession) => Effect.Effect<"created" | "rate_limited" | "invalid", ArtifactRepositoryFailure>;
    readonly findGuestSession: (tokenDigest: string, requestTime: string) => Effect.Effect<GuestReviewSession | null, ArtifactRepositoryFailure>;
    readonly deleteExpiredGuestSessions: (expiredBefore: string, limit: number) => Effect.Effect<number, ArtifactRepositoryFailure>;
    readonly deleteExpiredGuestContentRows: (expiredBefore: string, limit: number) => Effect.Effect<number, ArtifactRepositoryFailure>;
  };
  readonly findArtifact: (projectId: string, artifactId: string) => Effect.Effect<unknown, ArtifactRepositoryFailure>;
  readonly secrets: ContentSecretProvider;
}

interface GuestReviewOperations {
  readonly enable: (command: {artifactId: string; principal: Principal; projectId: string | null}) => Effect.Effect<{createdAt: string; linkSecret: string}, GuestReviewFailure>;
  readonly revoke: (command: {artifactId: string; principal: Principal; projectId: string | null}) => Effect.Effect<void, GuestReviewFailure>;
  readonly status: (command: {artifactId: string; principal: Principal; projectId: string | null}) => Effect.Effect<{createdAt: string | null; enabled: boolean}, GuestReviewFailure>;
  readonly exchange: (command: {artifactId: string; displayName: string; secret: string}) => Effect.Effect<{csrfToken: string; expiresAt: string; reviewer: GuestReviewer; sessionToken: Redacted.Redacted}, GuestReviewFailure>;
  readonly authenticate: (token: Redacted.Redacted, requestTime: string) => Effect.Effect<GuestReviewSession | null, GuestReviewFailure>;
}

type GuestReviewFailure = ArtifactRepositoryFailure | AuthorizationDenied | ArtifactNotFound | GuestRateLimitExceeded | ProjectArchived | ProjectNotFound | IdentityRepositoryFailure | ProjectManagementFailure;

/** Creates and validates revocable, artifact-scoped guest review grants. */
export class GuestReviewService extends Context.Service<GuestReviewService, GuestReviewOperations>()("artifact-server/application/GuestReviewService") {
  static readonly layer = (dependencies: GuestReviewDependencies): Layer.Layer<GuestReviewService, never, AuthorizationService | ProjectManagementService | InstallationAccessService> => Layer.effect(
    GuestReviewService,
    Effect.gen(function*() {
      const authorization = yield* AuthorizationService;
      const projects = yield* ProjectManagementService;
      const identities = yield* InstallationAccessService;
      const creatorMayStillManage = Effect.fn("GuestReviewService.creatorMayStillManage")(function*(projectId: string, creatorId: string) {
        const principal = yield* identities.findActiveHumanPrincipal(creatorId);
        if (principal === null) return false;
        const mayManageArtifact = yield* authorization.requireArtifactManagement(principal).pipe(
          Effect.as(true),
          Effect.catchTag("AuthorizationDenied", () => Effect.succeed(false)),
        );
        if (!mayManageArtifact) return false;
        return yield* projects.resolveActiveProject({minimumRole: "editor", principal, projectId}).pipe(
          Effect.as(true),
          Effect.catchTag("AuthorizationDenied", () => Effect.succeed(false)),
          Effect.catchTag("ProjectNotFound", () => Effect.succeed(false)),
          Effect.catchTag("ProjectArchived", () => Effect.succeed(false)),
        );
      });
      const resolveManageableArtifact = Effect.fn("GuestReviewService.resolveManageableArtifact")(function*(command: {artifactId: string; principal: Principal; projectId: string | null}) {
        const project = yield* projects.resolveActiveProject({minimumRole: "editor", principal: command.principal, projectId: command.projectId});
        yield* authorization.requireArtifactManagement(command.principal);
        const invitation = yield* dependencies.repository.findGuestInvitation(project.id, command.artifactId);
        const artifact = yield* dependencies.findArtifact(project.id, command.artifactId);
        if (artifact === null) return yield* new ArtifactNotFound({message: "The artifact does not exist."});
        return {projectId: project.id, invitation};
      });
      const status = Effect.fn("GuestReviewService.status")(function*(command: {artifactId: string; principal: Principal; projectId: string | null}) {
        const result = yield* resolveManageableArtifact(command);
        return {createdAt: result.invitation?.createdAt ?? null, enabled: result.invitation !== null && result.invitation.revokedAt === null};
      });
      const enable = Effect.fn("GuestReviewService.enable")(function*(command: {artifactId: string; principal: Principal; projectId: string | null}) {
        const result = yield* resolveManageableArtifact(command);
        const now = DateTime.formatIso(yield* dependencies.clock.now);
        const issued = dependencies.secrets.issue();
        const invitation: GuestReviewInvitation = {artifactId: command.artifactId, createdAt: now, createdByPrincipalId: command.principal.id, id: dependencies.ids.guestInvitationId(), projectId: result.projectId, revokedAt: null, tokenDigest: issued.digest};
        if (result.invitation !== null && result.invitation.revokedAt === null) yield* dependencies.repository.revokeGuestInvitation(result.projectId, command.artifactId, now);
        yield* dependencies.repository.createGuestInvitation(invitation);
        return {createdAt: now, linkSecret: Redacted.value(issued.token)};
      });
      const revoke = Effect.fn("GuestReviewService.revoke")(function*(command: {artifactId: string; principal: Principal; projectId: string | null}) {
        const result = yield* resolveManageableArtifact(command);
        if (result.invitation !== null && result.invitation.revokedAt === null) yield* dependencies.repository.revokeGuestInvitation(result.projectId, command.artifactId, DateTime.formatIso(yield* dependencies.clock.now));
      });
      const exchange = Effect.fn("GuestReviewService.exchange")(function*(command: {artifactId: string; displayName: string; secret: string}) {
        const now = yield* dependencies.clock.now;
        const nowIso = DateTime.formatIso(now);
        yield* dependencies.repository.deleteExpiredGuestContentRows(nowIso, 100);
        const displayName = command.displayName.trim();
        if (displayName.length < 1 || displayName.length > 80) return yield* new AuthorizationDenied({message: "The display name must contain 1 to 80 characters."});
        const invitation = yield* dependencies.repository.findGuestInvitationByDigest(dependencies.secrets.digest(Redacted.make(command.secret, {label: "guest-invitation"})));
        if (invitation === null || invitation.artifactId !== command.artifactId || invitation.revokedAt !== null) return yield* new ArtifactNotFound({message: "The requested route does not exist."});
        if (!(yield* creatorMayStillManage(invitation.projectId, invitation.createdByPrincipalId))) return yield* new ArtifactNotFound({message: "The requested route does not exist."});
        const sessionSecret = dependencies.secrets.issue();
        const csrfSecret = dependencies.secrets.issue();
        const absoluteExpiresAt = DateTime.formatIso(DateTime.addDuration(now, guestSessionLifetimeMilliseconds));
        const idleExpiresAt = DateTime.formatIso(DateTime.addDuration(now, guestIdleLifetimeMilliseconds));
        const guestId = dependencies.ids.guestSessionId();
        const created = yield* dependencies.repository.createGuestSession({absoluteExpiresAt, artifactId: invitation.artifactId, createdAt: nowIso, csrfDigest: csrfSecret.digest, displayName, expiresAt: idleExpiresAt, guestId, invitationCreatorPrincipalId: invitation.createdByPrincipalId, invitationId: invitation.id, lastUsedAt: nowIso, projectId: invitation.projectId, tokenDigest: sessionSecret.digest});
        if (created === "rate_limited") return yield* new GuestRateLimitExceeded({message: "This invitation has reached its exchange limit. Try again later."});
        if (created === "invalid") return yield* new ArtifactNotFound({message: "The requested route does not exist."});
        return {csrfToken: Redacted.value(csrfSecret.token), expiresAt: absoluteExpiresAt, reviewer: {artifactId: invitation.artifactId, displayName, guestId, invitationCreatorPrincipalId: invitation.createdByPrincipalId, projectId: invitation.projectId}, sessionToken: sessionSecret.token};
      });
      const authenticate = (token: Redacted.Redacted, requestTime: string) => Effect.gen(function*() {
        yield* dependencies.repository.deleteExpiredGuestSessions(requestTime, 100);
        const session = yield* dependencies.repository.findGuestSession(dependencies.secrets.digest(token), requestTime);
        if (session === null || !(yield* creatorMayStillManage(session.projectId, session.invitationCreatorPrincipalId))) return null;
        return session;
      });
      return GuestReviewService.of({authenticate, enable, exchange, revoke, status});
    }),
  );
}
