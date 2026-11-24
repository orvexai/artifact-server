import {Context, DateTime, Effect, Layer, Redacted} from "effect";
import {timingSafeEqual} from "node:crypto";

import {AuthorizationService} from "./authorization.js";
import {InstallationAccessService} from "./installation-access.js";
import {ProjectManagementService, type ProjectManagementFailure} from "./project-management.js";
import type {ApplicationClock} from "./application-clock.js";
import type {ContentSecretProvider} from "./content-access.js";
import {ArtifactNotFound, AuthorizationDenied, GuestRateLimitExceeded, type ArtifactRepositoryFailure, type IdentityRepositoryFailure, type ProjectArchived, type ProjectNotFound} from "../core/errors.js";
import type {Principal} from "../core/identity.js";
import {isReservedTenantIdentityName} from "../core/identity.js";
import type {ArtifactRecord, GuestReviewInvitation, GuestReviewInvitationUsage, GuestReviewSession, GuestReviewSessionSummary} from "../core/model.js";
import type {IdGenerator} from "../core/ports.js";
import {sealPublicLinkSecret, unsealPublicLinkSecret} from "./public-link-seal.js";

const guestIdleLifetimeMilliseconds = 2 * 60 * 60 * 1_000;
const guestSessionLifetimeMilliseconds = 7 * 24 * 60 * 60 * 1_000;

function constantTimeDigestEqual(actual: string, expected: string): boolean {
  const actualBytes = Buffer.from(actual);
  const expectedBytes = Buffer.from(expected);
  const comparisonLength = Math.max(actualBytes.byteLength, expectedBytes.byteLength, 1);
  const paddedActual = Buffer.alloc(comparisonLength);
  const paddedExpected = Buffer.alloc(comparisonLength);
  actualBytes.copy(paddedActual);
  expectedBytes.copy(paddedExpected);
  const equalBytes = timingSafeEqual(paddedActual, paddedExpected);
  return equalBytes && actualBytes.byteLength === expectedBytes.byteLength;
}

/** Identity carried by requests after the guest cookie has been verified. */
export interface GuestReviewer {
  readonly artifactId: string;
  readonly displayName: string;
  readonly nameRequired: boolean;
  readonly guestId: string;
  readonly invitationCreatorPrincipalId: string;
  readonly projectId: string;
  readonly permission: "view" | "comment";
  readonly paused: boolean;
}

export interface GuestSessionExchangeCommand {
  artifactId: string;
  displayName?: string;
  existingCsrfToken?: string;
  existingSessionToken?: string;
  secret: string;
}

export interface GuestReviewDependencies {
  readonly clock: ApplicationClock;
  readonly ids: IdGenerator;
  readonly installationId: string;
  readonly publicLinkKey?: Uint8Array;
  readonly publicLinkKeyPrevious?: Uint8Array;
  readonly organizationDirectoryVisibility?: boolean | undefined;
  readonly repository: {
    readonly createGuestInvitation: (invitation: GuestReviewInvitation) => Effect.Effect<"created" | "exists" | "disabled", ArtifactRepositoryFailure>;
    readonly getPublicLinksEnabled: () => Effect.Effect<boolean, ArtifactRepositoryFailure>;
    readonly resetGuestInvitation: (invitation: GuestReviewInvitation) => Effect.Effect<"updated" | "missing" | "disabled", ArtifactRepositoryFailure>;
    readonly resealGuestInvitation: (invitationId: string, generation: number, oldFingerprint: string, sealedSecret: string, currentFingerprint: string) => Effect.Effect<boolean, ArtifactRepositoryFailure>;
    readonly findGuestInvitation: (projectId: string, artifactId: string) => Effect.Effect<GuestReviewInvitation | null, ArtifactRepositoryFailure>;
    readonly findGuestInvitationByDigest: (tokenDigest: string) => Effect.Effect<GuestReviewInvitation | null, ArtifactRepositoryFailure>;
    readonly revokeGuestInvitation: (projectId: string, artifactId: string, revokedAt: string) => Effect.Effect<boolean, ArtifactRepositoryFailure>;
    readonly setGuestInvitationPermission: (invitationId: string, permission: "view" | "comment", updatedAt: string, updatedByPrincipalId: string) => Effect.Effect<boolean, ArtifactRepositoryFailure>;
    readonly createGuestSession: (session: GuestReviewSession) => Effect.Effect<"created" | "rate_limited" | "invalid", ArtifactRepositoryFailure>;
    readonly findGuestSessionByTokenDigest: (tokenDigest: string, requestTime: string) => Effect.Effect<GuestReviewSession | null, ArtifactRepositoryFailure>;
    readonly findGuestSession: (tokenDigest: string, artifactId: string, requestTime: string) => Effect.Effect<GuestReviewSession | null, ArtifactRepositoryFailure>;
    readonly listGuestSessions: (projectId: string, artifactId: string, requestTime: string) => Effect.Effect<readonly GuestReviewSessionSummary[], ArtifactRepositoryFailure>;
    readonly revokeGuestSession: (projectId: string, artifactId: string, guestId: string) => Effect.Effect<boolean, ArtifactRepositoryFailure>;
    readonly updateGuestSessionDisplayName: (projectId: string, artifactId: string, guestId: string, displayName: string) => Effect.Effect<boolean, ArtifactRepositoryFailure>;
    readonly getGuestInvitationUsage: (invitationId: string, requestTime: string) => Effect.Effect<GuestReviewInvitationUsage, ArtifactRepositoryFailure>;
    readonly deleteExpiredGuestSessions: (expiredBefore: string, limit: number) => Effect.Effect<number, ArtifactRepositoryFailure>;
    readonly deleteExpiredGuestContentRows: (expiredBefore: string, limit: number) => Effect.Effect<number, ArtifactRepositoryFailure>;
  };
  readonly findArtifact: (projectId: string, artifactId: string) => Effect.Effect<ArtifactRecord | null, ArtifactRepositoryFailure>;
  readonly secrets: ContentSecretProvider;
}

interface GuestReviewOperations {
  readonly create: (command: {artifactId: string; permission?: "view" | "comment"; principal: Principal; projectId: string | null}) => Effect.Effect<{createdAt: string; linkSecret: string} | "exists" | "disabled", GuestReviewFailure>;
  readonly enable: (command: {artifactId: string; permission?: "view" | "comment"; principal: Principal; projectId: string | null}) => Effect.Effect<{createdAt: string; linkSecret: string}, GuestReviewFailure>;
  readonly revoke: (command: {artifactId: string; principal: Principal; projectId: string | null}) => Effect.Effect<void, GuestReviewFailure>;
  readonly status: (command: {artifactId: string; principal: Principal; projectId: string | null}) => Effect.Effect<{activeSessionCount: number; createdAt: string | null; enabled: boolean; legacy: boolean; limitHitRecently: boolean; linkSecret: string | null; permission: "view" | "comment"; updatedAt: string | null}, GuestReviewFailure>;
  readonly setPermission: (command: {artifactId: string; permission: "view" | "comment"; principal: Principal; projectId: string | null}) => Effect.Effect<"legacy" | "updated", GuestReviewFailure>;
  readonly listSessions: (command: {artifactId: string; principal: Principal; projectId: string | null}) => Effect.Effect<readonly GuestReviewSessionSummary[], GuestReviewFailure>;
  readonly revokeSession: (command: {artifactId: string; guestId: string; principal: Principal; projectId: string | null}) => Effect.Effect<void, GuestReviewFailure>;
  readonly renameCurrent: (command: {artifactId: string; displayName: string; guest: GuestReviewer}) => Effect.Effect<string, GuestReviewFailure>;
  readonly policyEnabled: () => Effect.Effect<boolean, ArtifactRepositoryFailure>;
    readonly exchange: (command: GuestSessionExchangeCommand) => Effect.Effect<{csrfToken: string; expiresAt: string; reviewer: GuestReviewer; sessionToken: Redacted.Redacted}, GuestReviewFailure>;
  readonly authenticate: (token: Redacted.Redacted, artifactId: string, requestTime: string) => Effect.Effect<GuestReviewSession | null, GuestReviewFailure>;
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
        return yield* projects.getProject({minimumRole: "editor", principal, projectId}).pipe(
          Effect.as(true),
          Effect.catchTag("AuthorizationDenied", () => Effect.succeed(false)),
          Effect.catchTag("ProjectNotFound", () => Effect.succeed(false)),
        );
      });
      const resolveManageableArtifact = Effect.fn("GuestReviewService.resolveManageableArtifact")(function*(command: {artifactId: string; principal: Principal; projectId: string | null}) {
        const project = yield* projects.resolveActiveProject({minimumRole: "editor", principal: command.principal, projectId: command.projectId});
        yield* authorization.requireArtifactManagement(command.principal);
        const invitation = yield* dependencies.repository.findGuestInvitation(project.id, command.artifactId);
        const artifact = yield* dependencies.findArtifact(project.id, command.artifactId);
        if (artifact === null) return yield* new ArtifactNotFound({message: "The artifact does not exist."});
        return {artifact, projectId: project.id, invitation};
      });
      const requireHumanCreator = Effect.fn("GuestReviewService.requireHumanCreator")(function*(projectId: string, creatorId: string) {
        if (!(yield* creatorMayStillManage(projectId, creatorId))) {
          return yield* new AuthorizationDenied({
            code: "PUBLIC_LINK_HUMAN_CREATOR_REQUIRED",
            message: "Sign in as a person or use a person's own key to create, reset, or enable a public link.",
          });
        }
        return undefined;
      });
      const status = Effect.fn("GuestReviewService.status")(function*(command: {artifactId: string; principal: Principal; projectId: string | null}) {
        const result = yield* resolveManageableArtifact(command);
        const now = DateTime.formatIso(yield* dependencies.clock.now);
        const invitation = result.invitation;
        const enabled = invitation !== null && invitation.revokedAt === null;
        const usage = enabled && invitation !== null ? yield* dependencies.repository.getGuestInvitationUsage(invitation.id, now) : {activeSessionCount: 0, limitHitRecently: false};
        let linkSecret: string | null = enabled && invitation?.sealedSecret !== null && invitation !== null
          ? (dependencies.publicLinkKey === undefined ? null : unsealPublicLinkSecret({
            installationId: dependencies.installationId, key: dependencies.publicLinkKey,
            linkId: invitation.id, generation: invitation.generation, sealed: invitation.sealedSecret,
          }))
          : null;
        if (linkSecret === null && enabled && invitation?.sealedSecret !== null && invitation !== null &&
          dependencies.publicLinkKey !== undefined && dependencies.publicLinkKeyPrevious !== undefined &&
          invitation.sealKeyFingerprint !== null) {
          const previousSecret = unsealPublicLinkSecret({
            installationId: dependencies.installationId, key: dependencies.publicLinkKeyPrevious,
            linkId: invitation.id, generation: invitation.generation, sealed: invitation.sealedSecret,
          });
          if (previousSecret !== null) {
            const resealed = sealPublicLinkSecret({
              installationId: dependencies.installationId, key: dependencies.publicLinkKey,
              linkId: invitation.id, generation: invitation.generation, secret: previousSecret,
            });
            yield* dependencies.repository.resealGuestInvitation(
              invitation.id, invitation.generation, invitation.sealKeyFingerprint,
              resealed.sealed, resealed.fingerprint,
            );
            linkSecret = previousSecret;
          }
        }
        return {activeSessionCount: usage.activeSessionCount, createdAt: invitation?.createdAt ?? null, enabled, limitHitRecently: usage.limitHitRecently,
          legacy: result.artifact.accessSetting === "public_link", linkSecret,
          permission: invitation?.permission ?? "view", updatedAt: invitation?.updatedAt ?? null};
      });
      const setPermission = Effect.fn("GuestReviewService.setPermission")(function*(command: {artifactId: string; permission: "view" | "comment"; principal: Principal; projectId: string | null}) {
        const result = yield* resolveManageableArtifact(command);
        if (result.artifact.accessSetting === "public_link" && command.permission === "comment") return "legacy" as const;
        if (result.invitation === null || result.invitation.revokedAt !== null) return yield* new ArtifactNotFound({message: "The public link does not exist."});
        const updatedAt = DateTime.formatIso(yield* dependencies.clock.now);
        const updated = yield* dependencies.repository.setGuestInvitationPermission(result.invitation.id, command.permission, updatedAt, command.principal.id);
        if (!updated) return yield* new ArtifactNotFound({message: "The public link does not exist."});
        return "updated" as const;
      });
      const listSessions = Effect.fn("GuestReviewService.listSessions")(function*(command: {artifactId: string; principal: Principal; projectId: string | null}) {
        const result = yield* resolveManageableArtifact(command);
        if (result.invitation === null || result.invitation.revokedAt !== null) return [];
        const sessions = yield* dependencies.repository.listGuestSessions(result.projectId, command.artifactId, DateTime.formatIso(yield* dependencies.clock.now));
        return dependencies.organizationDirectoryVisibility === true
          ? sessions.map((session) => ({...session,
            displayName: session.displayName === null ? "Visitor" : isReservedTenantIdentityName(session.displayName) ? "Orvex Support (member)" : session.displayName,
          }))
          : sessions;
      });
      const revokeSession = Effect.fn("GuestReviewService.revokeSession")(function*(command: {artifactId: string; guestId: string; principal: Principal; projectId: string | null}) {
        const result = yield* resolveManageableArtifact(command);
        const revoked = yield* dependencies.repository.revokeGuestSession(result.projectId, command.artifactId, command.guestId);
        if (!revoked) return yield* new ArtifactNotFound({message: "The guest session does not exist."});
        return undefined;
      });
      const renameCurrent = Effect.fn("GuestReviewService.renameCurrent")(function*(command: {artifactId: string; displayName: string; guest: GuestReviewer}) {
        if (command.guest.artifactId !== command.artifactId || command.guest.permission !== "comment") return yield* new ArtifactNotFound({message: "The requested route does not exist."});
        const requestedDisplayName = command.displayName.trim();
        if (requestedDisplayName.length < 1 || requestedDisplayName.length > 80) return yield* new AuthorizationDenied({message: "The display name must contain 1 to 80 characters."});
        const displayName = dependencies.organizationDirectoryVisibility === true && isReservedTenantIdentityName(requestedDisplayName)
          ? "Orvex Support (member)"
          : requestedDisplayName;
        const updated = yield* dependencies.repository.updateGuestSessionDisplayName(command.guest.projectId, command.artifactId, command.guest.guestId, displayName);
        if (!updated) return yield* new ArtifactNotFound({message: "The requested route does not exist."});
        return displayName;
      });
      const policyEnabled = () => dependencies.repository.getPublicLinksEnabled();
      const enable = Effect.fn("GuestReviewService.enable")(function*(command: {artifactId: string; permission?: "view" | "comment"; principal: Principal; projectId: string | null}) {
        if (!(yield* dependencies.repository.getPublicLinksEnabled())) return yield* new AuthorizationDenied({message: "An administrator has disabled public links."});
        const result = yield* resolveManageableArtifact(command);
        yield* requireHumanCreator(result.projectId, command.principal.id);
        const now = DateTime.formatIso(yield* dependencies.clock.now);
        const issued = dependencies.secrets.issue();
        const id = dependencies.ids.guestInvitationId();
        const sealed = dependencies.publicLinkKey === undefined ? null : sealPublicLinkSecret({
          installationId: dependencies.installationId,
          key: dependencies.publicLinkKey,
          linkId: id,
          generation: (result.invitation?.generation ?? 0) + 1,
          secret: Redacted.value(issued.token),
        });
        const invitation: GuestReviewInvitation = {artifactId: command.artifactId, createdAt: now, createdByPrincipalId: command.principal.id, generation: (result.invitation?.generation ?? 0) + 1, id, permission: command.permission ?? "comment", paused: false, projectId: result.projectId, revokedAt: null, sealedSecret: sealed?.sealed ?? null, sealKeyFingerprint: sealed?.fingerprint ?? null, tokenDigest: issued.digest, updatedAt: now, updatedByPrincipalId: command.principal.id};
        const reset = yield* dependencies.repository.resetGuestInvitation(invitation);
        if (reset === "disabled") return yield* new AuthorizationDenied({message: "An administrator has disabled public links."});
        if (reset === "missing") return yield* new ArtifactNotFound({message: "The artifact does not exist."});
        return {createdAt: now, linkSecret: Redacted.value(issued.token)};
      });
      const create = Effect.fn("GuestReviewService.create")(function*(command: {artifactId: string; permission?: "view" | "comment"; principal: Principal; projectId: string | null}) {
        if (!(yield* dependencies.repository.getPublicLinksEnabled())) return "disabled" as const;
        const result = yield* resolveManageableArtifact(command);
        yield* requireHumanCreator(result.projectId, command.principal.id);
        if (result.invitation !== null && result.invitation.revokedAt === null) return "exists" as const;
        const now = DateTime.formatIso(yield* dependencies.clock.now);
        const issued = dependencies.secrets.issue();
        const id = dependencies.ids.guestInvitationId();
        const generation = (result.invitation?.generation ?? 0) + 1;
        const sealed = dependencies.publicLinkKey === undefined ? null : sealPublicLinkSecret({
          installationId: dependencies.installationId, key: dependencies.publicLinkKey,
          linkId: id, generation, secret: Redacted.value(issued.token),
        });
        const invitation: GuestReviewInvitation = {
          artifactId: command.artifactId, createdAt: now,
          createdByPrincipalId: command.principal.id, generation, id,
          permission: command.permission ?? "view", projectId: result.projectId,
          paused: false,
          revokedAt: null, sealedSecret: sealed?.sealed ?? null,
          sealKeyFingerprint: sealed?.fingerprint ?? null, tokenDigest: issued.digest,
          updatedAt: now, updatedByPrincipalId: command.principal.id,
        };
        const writeResult = yield* dependencies.repository.createGuestInvitation(invitation);
        if (writeResult !== "created") return writeResult;
        return {createdAt: now, linkSecret: Redacted.value(issued.token)};
      });
      const revoke = Effect.fn("GuestReviewService.revoke")(function*(command: {artifactId: string; principal: Principal; projectId: string | null}) {
        const result = yield* resolveManageableArtifact(command);
        if (result.invitation !== null && result.invitation.revokedAt === null) yield* dependencies.repository.revokeGuestInvitation(result.projectId, command.artifactId, DateTime.formatIso(yield* dependencies.clock.now));
      });
      const exchange = Effect.fn("GuestReviewService.exchange")(function*(command: GuestSessionExchangeCommand) {
        const now = yield* dependencies.clock.now;
        const nowIso = DateTime.formatIso(now);
        yield* dependencies.repository.deleteExpiredGuestContentRows(nowIso, 100);
        const invitation = yield* dependencies.repository.findGuestInvitationByDigest(dependencies.secrets.digest(Redacted.make(command.secret, {label: "guest-invitation"})));
        if (invitation === null || invitation.artifactId !== command.artifactId || invitation.revokedAt !== null) return yield* new ArtifactNotFound({message: "The requested route does not exist."});
        if (!(yield* creatorMayStillManage(invitation.projectId, invitation.createdByPrincipalId))) return yield* new ArtifactNotFound({message: "The requested route does not exist."});
        const requestedDisplayName = command.displayName?.trim() ?? "";
        if (command.displayName !== undefined && (requestedDisplayName.length < 1 || requestedDisplayName.length > 80)) return yield* new AuthorizationDenied({message: "The display name must contain 1 to 80 characters."});
        const displayName = requestedDisplayName.length === 0 ? null : dependencies.organizationDirectoryVisibility === true && isReservedTenantIdentityName(requestedDisplayName)
          ? "Orvex Support (member)"
          : requestedDisplayName;
        const existing = command.existingSessionToken === undefined || command.existingCsrfToken === undefined
          ? null
          : yield* dependencies.repository.findGuestSessionByTokenDigest(
            dependencies.secrets.digest(Redacted.make(command.existingSessionToken, {label: "guest-session"})), nowIso,
          );
        const reusable = existing !== null && command.existingCsrfToken !== undefined &&
          command.existingSessionToken !== undefined &&
          constantTimeDigestEqual(existing.csrfDigest, dependencies.secrets.digest(
            Redacted.make(command.existingCsrfToken, {label: "guest-csrf"}),
          )) ? {existing, csrfToken: command.existingCsrfToken, sessionToken: command.existingSessionToken} : null;
        if (reusable !== null && reusable.existing.artifactId === invitation.artifactId && reusable.existing.invitationId === invitation.id) {
          return {csrfToken: reusable.csrfToken, expiresAt: reusable.existing.absoluteExpiresAt,
            reviewer: {artifactId: reusable.existing.artifactId, displayName: reusable.existing.displayName ?? "Visitor", nameRequired: reusable.existing.displayName === null && reusable.existing.permission === "comment" && !reusable.existing.paused, guestId: reusable.existing.guestId,
              invitationCreatorPrincipalId: reusable.existing.invitationCreatorPrincipalId, permission: reusable.existing.permission, paused: reusable.existing.paused, projectId: reusable.existing.projectId},
            sessionToken: Redacted.make(reusable.sessionToken, {label: "guest-session"})};
        }
        let sessionSecret: Redacted.Redacted;
        let sessionDigest: string;
        let csrfToken: Redacted.Redacted;
        let csrfDigest: string;
        if (reusable === null) {
          const issuedSessionSecret = dependencies.secrets.issue();
          sessionSecret = issuedSessionSecret.token;
          sessionDigest = issuedSessionSecret.digest;
          const issuedCsrfSecret = dependencies.secrets.issue();
          csrfToken = issuedCsrfSecret.token;
          csrfDigest = issuedCsrfSecret.digest;
        } else {
          sessionSecret = Redacted.make(reusable.sessionToken, {label: "guest-session"});
          sessionDigest = dependencies.secrets.digest(sessionSecret);
          csrfToken = Redacted.make(reusable.csrfToken, {label: "guest-csrf"});
          csrfDigest = reusable.existing.csrfDigest;
        }
        const absoluteExpiresAt = DateTime.formatIso(DateTime.addDuration(now, guestSessionLifetimeMilliseconds));
        const idleExpiresAt = DateTime.formatIso(DateTime.addDuration(now, guestIdleLifetimeMilliseconds));
        const guestId = dependencies.ids.guestSessionId();
        const created = yield* dependencies.repository.createGuestSession({absoluteExpiresAt, artifactId: invitation.artifactId, createdAt: nowIso, csrfDigest, displayName, expiresAt: idleExpiresAt, guestId, invitationCreatorPrincipalId: invitation.createdByPrincipalId, invitationId: invitation.id, lastUsedAt: nowIso, permission: invitation.permission, paused: false, projectId: invitation.projectId, tokenDigest: sessionDigest});
        if (created === "rate_limited") return yield* new GuestRateLimitExceeded({message: "This invitation has reached its exchange limit. Try again later."});
        if (created === "invalid") return yield* new ArtifactNotFound({message: "The requested route does not exist."});
        const paused = invitation.paused;
        return {csrfToken: Redacted.value(csrfToken), expiresAt: absoluteExpiresAt, reviewer: {artifactId: invitation.artifactId, displayName: displayName ?? "Visitor", nameRequired: displayName === null && invitation.permission === "comment" && !paused, guestId, invitationCreatorPrincipalId: invitation.createdByPrincipalId, permission: invitation.permission, paused, projectId: invitation.projectId}, sessionToken: sessionSecret};
      });
      let lastGuestContentSweepAt = 0;
      const authenticate = (token: Redacted.Redacted, artifactId: string, requestTime: string) => Effect.gen(function*() {
        const requestTimestamp = Date.parse(requestTime);
        if (requestTimestamp - lastGuestContentSweepAt >= 60_000) {
          yield* dependencies.repository.deleteExpiredGuestContentRows(requestTime, 100);
          lastGuestContentSweepAt = requestTimestamp;
        }
        yield* dependencies.repository.deleteExpiredGuestSessions(requestTime, 100);
        const session = yield* dependencies.repository.findGuestSession(dependencies.secrets.digest(token), artifactId, requestTime);
        if (session === null || !(yield* creatorMayStillManage(session.projectId, session.invitationCreatorPrincipalId))) return null;
        return session;
      });
      return GuestReviewService.of({authenticate, create, enable, exchange, listSessions, policyEnabled, renameCurrent, revoke, revokeSession, setPermission, status});
    }),
  );
}
