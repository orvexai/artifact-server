import {Context, DateTime, Effect, Layer, Schema} from "effect";

import type {ApplicationClock} from "./application-clock.js";
import {
  type AuthorizationOperations,
  AuthorizationService,
} from "./authorization.js";
import {InstallationAccessService} from "./installation-access.js";
import {
  type ArtifactRepositoryFailure,
  AuthorizationDenied,
  DirectoryGroupNotFound,
  type IdentityRepositoryFailure,
  InvalidProjectName,
  ProjectArchived,
  type ProjectConflict,
  ProjectNotFound,
  ProjectSelectionRequired,
} from "../core/errors.js";
import {
  hasCapability,
  isDirectHumanPrincipal,
  principalCapabilities,
  principalKinds,
  type Principal,
} from "../core/identity.js";
import {
  type ProjectAccess,
  type ProjectAccessMode,
  type ProjectGrantRole,
  type ProjectRole,
  projectRoleAtLeast,
} from "../core/project-access.js";
import type {StoredDirectoryGroup} from "../core/directory-groups.js";
import type {ProjectAuditEvent, ProjectRecord} from "../core/model.js";
import type {
  CreateProject,
  IdGenerator,
  RenameProject,
  SetProjectArchive,
} from "../core/ports.js";

const projectNameSchema = Schema.Trim.check(Schema.isLengthBetween(1, 120));
const decodeProjectName = Schema.decodeUnknownEffect(projectNameSchema);

/** One group to share a project with: an id, full path, or unique name. */
export interface ProjectGroupShare {
  readonly group: string;
  readonly role: ProjectGrantRole;
}

/** Input for creating one project inside the current installation. */
export interface CreateProjectCommand {
  readonly name: string;
  readonly principal: Principal;
  /** Groups the new, restricted project is shared with as it is created. */
  readonly shareWith?: readonly ProjectGroupShare[];
}

/** Input for changing who may see one project. */
export interface SetProjectAccessCommand extends ReadProjectCommand {
  readonly accessMode: ProjectAccessMode;
}

/** Input for sharing one project with one group. */
export interface ShareProjectCommand extends ReadProjectCommand, ProjectGroupShare {}

/** Input for removing one group's share of one project. */
export interface UnshareProjectCommand extends ReadProjectCommand {
  readonly group: string;
}

/** One group a project is shared with. */
export interface ProjectGroupShareView {
  readonly grantedAt: string;
  readonly groupId: string;
  readonly name: string;
  readonly path: string;
  readonly role: ProjectGrantRole;
}

/** One project the caller can see, with how it can see it. */
export interface VisibleProject {
  readonly accessMode: ProjectAccessMode;
  readonly project: ProjectRecord;
  /** Null on an installation project, where today's rules apply. */
  readonly yourRole: ProjectRole | null;
}

/** Who may see one project, and the caller's own role on it. */
export interface ProjectSharing {
  readonly accessMode: ProjectAccessMode;
  readonly groups: readonly ProjectGroupShareView[];
  readonly projectId: string;
  /** Null on an installation project, where today's rules apply. */
  readonly yourRole: ProjectRole | null;
}

/** Input for selecting one active project, with omission allowed for zero-setup use. */
export interface ResolveActiveProjectCommand {
  /** The weakest role a restricted project must grant; viewer when omitted. */
  readonly minimumRole?: ProjectRole;
  readonly principal: Principal;
  readonly projectId: string | null;
}

/** Input for reading one project inside the current installation. */
export interface ReadProjectCommand {
  /** The weakest role a restricted project must grant; viewer when omitted. */
  readonly minimumRole?: ProjectRole;
  readonly principal: Principal;
  readonly projectId: string;
}

/** Input for changing one project's label. */
export interface RenameProjectCommand extends ReadProjectCommand {
  readonly name: string;
}

/** Persistence required by project lifecycle operations. */
export interface ProjectManagementRepository {
  readonly createProject: (
    command: CreateProject,
  ) => Effect.Effect<ProjectRecord, ProjectConflict | ArtifactRepositoryFailure>;
  readonly findProject: (
    projectId: string,
  ) => Effect.Effect<ProjectRecord | null, ArtifactRepositoryFailure>;
  readonly listProjects: () => Effect.Effect<
    readonly ProjectRecord[],
    ArtifactRepositoryFailure
  >;
  readonly listProjectAuditEvents: (
    projectId: string,
  ) => Effect.Effect<readonly ProjectAuditEvent[], ArtifactRepositoryFailure>;
  readonly renameProject: (
    command: RenameProject,
  ) => Effect.Effect<ProjectRecord, ProjectNotFound | ArtifactRepositoryFailure>;
  readonly setProjectArchive: (
    command: SetProjectArchive,
  ) => Effect.Effect<
    ProjectRecord,
    ProjectConflict | ProjectNotFound | ArtifactRepositoryFailure
  >;
}

/** Dependencies used to construct project lifecycle operations. */
export interface ProjectManagementDependencies {
  readonly clock: ApplicationClock;
  readonly ids: IdGenerator;
  readonly installationId: string;
  readonly repository: ProjectManagementRepository;
}

/** Expected failures produced by project lifecycle operations. */
export type ProjectManagementFailure =
  | ArtifactRepositoryFailure
  | AuthorizationDenied
  | DirectoryGroupNotFound
  | IdentityRepositoryFailure
  | InvalidProjectName
  | ProjectArchived
  | ProjectConflict
  | ProjectNotFound
  | ProjectSelectionRequired;

interface ProjectManagementOperations {
  readonly archiveProject: (
    command: ReadProjectCommand,
  ) => Effect.Effect<ProjectRecord, ProjectManagementFailure>;
  readonly createProject: (
    command: CreateProjectCommand,
  ) => Effect.Effect<ProjectRecord, ProjectManagementFailure>;
  /** Who may see one project; anyone who can see it may read this. */
  readonly getSharing: (
    command: ReadProjectCommand,
  ) => Effect.Effect<ProjectSharing, ProjectManagementFailure>;
  /** Restrict a project or open it to every member; needs a manager. */
  readonly setAccessMode: (
    command: SetProjectAccessCommand,
  ) => Effect.Effect<ProjectSharing, ProjectManagementFailure>;
  /** Share a project with a group, or change its role; needs a manager. */
  readonly shareWithGroup: (
    command: ShareProjectCommand,
  ) => Effect.Effect<ProjectSharing, ProjectManagementFailure>;
  /** Stop sharing a project with a group; needs a manager. */
  readonly unshareGroup: (
    command: UnshareProjectCommand,
  ) => Effect.Effect<ProjectSharing, ProjectManagementFailure>;
  readonly getProject: (
    command: ReadProjectCommand,
  ) => Effect.Effect<ProjectRecord, ProjectManagementFailure>;
  readonly listProjects: (
    principal: Principal,
  ) => Effect.Effect<readonly ProjectRecord[], ProjectManagementFailure>;
  /** Every visible project with its access mode and the caller's role. */
  readonly listProjectsWithAccess: (
    principal: Principal,
  ) => Effect.Effect<readonly VisibleProject[], ProjectManagementFailure>;
  readonly listAuditEvents: (
    command: ReadProjectCommand,
  ) => Effect.Effect<readonly ProjectAuditEvent[], ProjectManagementFailure>;
  readonly renameProject: (
    command: RenameProjectCommand,
  ) => Effect.Effect<ProjectRecord, ProjectManagementFailure>;
  /**
   * Require the right to manage one project's settings: an installation
   * project manager, or the project's own manager once it is restricted.
   */
  readonly requireManagement: (
    command: ReadProjectCommand,
  ) => Effect.Effect<ProjectRecord, ProjectManagementFailure>;
  /**
   * Whether the principal that owns something, known only by its id, may
   * see one project: used before handing project content to someone's agent.
   */
  readonly ownerCanView: (
    ownerPrincipalId: string,
    projectId: string,
  ) => Effect.Effect<boolean, IdentityRepositoryFailure>;
  readonly resolveActiveProject: (
    command: ResolveActiveProjectCommand,
  ) => Effect.Effect<ProjectRecord, ProjectManagementFailure>;
  readonly unarchiveProject: (
    command: ReadProjectCommand,
  ) => Effect.Effect<ProjectRecord, ProjectManagementFailure>;
}

/** Owns project selection and lifecycle policy for one installation. */
export class ProjectManagementService extends Context.Service<
  ProjectManagementService,
  ProjectManagementOperations
>()("artifact-server/application/ProjectManagementService") {
  /** Construct project operations from deployment-neutral persistence. */
  static readonly layer = (
    dependencies: ProjectManagementDependencies,
  ): Layer.Layer<
    ProjectManagementService,
    never,
    AuthorizationService | InstallationAccessService
  > =>
    Layer.effect(
      ProjectManagementService,
      Effect.gen(function*() {
        const authorization = yield* AuthorizationService;
        const access = yield* InstallationAccessService;
        return makeProjectManagementService(dependencies, authorization, access);
      }),
    );
}

function makeProjectManagementService(
  dependencies: ProjectManagementDependencies,
  authorization: AuthorizationOperations,
  access: InstallationAccessService["Service"],
): ProjectManagementOperations {
  /**
   * Find one project the principal may see with at least `minimumRole`. A
   * restricted project the principal cannot see is reported as absent; one
   * it can see but not at that role is denied. An installation project keeps
   * today's rules, which the caller's own capability checks apply.
   */
  const requireProjectWithAccess = Effect.fn(
    "ProjectManagementService.requireProjectWithAccess",
  )(function*(
    principal: Principal,
    projectId: string,
    minimumRole: ProjectRole,
  ): Effect.fn.Return<
    {readonly access: ProjectAccess; readonly project: ProjectRecord},
    | ArtifactRepositoryFailure
    | AuthorizationDenied
    | IdentityRepositoryFailure
    | ProjectNotFound
  > {
    yield* authorization.requireProjectAccess(principal);
    const project = yield* dependencies.repository.findProject(projectId);
    const projectAccess = project !== null &&
        project.installationId === dependencies.installationId
      ? yield* access.projectAccess(principal, project.id)
      : null;
    if (
      project === null || projectAccess === null ||
      (projectAccess.mode === "restricted" && projectAccess.role === null)
    ) {
      return yield* new ProjectNotFound({message: "The project does not exist."});
    }
    if (
      projectAccess.mode === "restricted" && projectAccess.role !== null &&
      !projectRoleAtLeast(projectAccess.role, minimumRole)
    ) {
      return yield* new AuthorizationDenied({
        message: `This action needs the ${minimumRole} role on the project.`,
      });
    }
    yield* Effect.annotateCurrentSpan({"artifact.project.id": project.id});
    return {access: projectAccess, project};
  });

  const requireProject = Effect.fn("ProjectManagementService.requireProject")(
    function*(principal: Principal, projectId: string, minimumRole: ProjectRole = "viewer") {
      return (yield* requireProjectWithAccess(principal, projectId, minimumRole)).project;
    },
  );

  /**
   * Allow rename, archive, settings and audit reads. On an installation
   * project the installation rule decides, exactly as before: an
   * administrator, or a key that can manage projects. On a restricted
   * project a member needs the manager role there, through a session or a
   * key that can manage projects; an installation-wide key alone is not
   * enough, since a member's key reaches only what the member can. A
   * failure keeps today's answer: denied, not "not found".
   */
  const requireManagedProject = Effect.fn(
    "ProjectManagementService.requireManagedProject",
  )(function*(principal: Principal, projectId: string) {
    const denial = new AuthorizationDenied({message: "Project management is required."});
    const installationWide = yield* authorization.requireProjectManagement(principal).pipe(
      Effect.as(true),
      Effect.catchTag("AuthorizationDenied", () => Effect.succeed(false)),
    );
    const found = yield* requireProjectWithAccess(principal, projectId, "viewer").pipe(
      Effect.catchTag("ProjectNotFound", (notFound) =>
        Effect.fail<ProjectNotFound | AuthorizationDenied>(
          installationWide ? notFound : denial,
        )
      ),
    );
    if (found.access.mode === "installation" || found.access.role === "administrator") {
      if (installationWide) return found.project;
      // A creator who opened their project to everyone can still restrict it.
      if (
        found.access.mode === "installation" && found.access.isCreator &&
        (isDirectHumanPrincipal(principal) ||
          hasCapability(principal, principalCapabilities.manageProjects))
      ) {
        return found.project;
      }
      return yield* denial;
    }
    if (
      found.access.role === "manager" &&
      (isDirectHumanPrincipal(principal) ||
        hasCapability(principal, principalCapabilities.manageProjects))
    ) {
      return found.project;
    }
    return yield* denial;
  });

  /** Every project the principal may see, with the access that showed it. */
  const listVisibleProjects = Effect.fn("ProjectManagementService.listVisibleProjects")(
    function*(principal: Principal) {
      yield* authorization.requireProjectAccess(principal);
      const all = yield* dependencies.repository.listProjects();
      const visible: {readonly access: ProjectAccess; readonly project: ProjectRecord}[] = [];
      for (const project of all) {
        const projectAccess = yield* access.projectAccess(principal, project.id);
        if (
          projectAccess !== null &&
          (projectAccess.mode === "installation" || projectAccess.role !== null)
        ) {
          visible.push({access: projectAccess, project});
        }
      }
      return visible;
    },
  );

  const listProjects = Effect.fn("ProjectManagementService.listProjects")(
    function*(principal: Principal) {
      return (yield* listVisibleProjects(principal)).map(({project}) => project);
    },
  );

  const listAuditEvents = Effect.fn(
    "ProjectManagementService.listAuditEvents",
  )(function*(command: ReadProjectCommand) {
    const project = yield* requireManagedProject(command.principal, command.projectId);
    return yield* dependencies.repository.listProjectAuditEvents(project.id);
  });

  const resolveActiveProject = Effect.fn(
    "ProjectManagementService.resolveActiveProject",
  )(function*(command: ResolveActiveProjectCommand) {
    if (command.projectId !== null) {
      const project = yield* requireProject(
        command.principal,
        command.projectId,
        command.minimumRole,
      );
      if (project.archivedAt !== null) {
        return yield* new ProjectArchived({
          message: "The project is archived and cannot accept new work.",
        });
      }
      return project;
    }
    const visible = (yield* listVisibleProjects(command.principal)).filter(
      ({project}) => project.archivedAt === null,
    );
    const projects = visible.map(({project}) => project);
    const only = visible.length === 1 ? visible[0] : undefined;
    if (only !== undefined) {
      // The one visible project must still grant the role this action needs.
      if (
        only.access.mode === "restricted" && only.access.role !== null &&
        !projectRoleAtLeast(only.access.role, command.minimumRole ?? "viewer")
      ) {
        return yield* new AuthorizationDenied({
          message: `This action needs the ${command.minimumRole ?? "viewer"} role on the project.`,
        });
      }
      yield* Effect.annotateCurrentSpan({"artifact.project.id": only.project.id});
      return only.project;
    }
    if (projects.length === 0) {
      return yield* new ProjectNotFound({
        message: "This installation has no active project.",
      });
    }
    return yield* new ProjectSelectionRequired({
      message: `Choose a project before continuing: ${projects.map(
        ({id, name}) => `${name} (${id})`,
      ).join(", ")}.`,
      projects: projects.map(({id, name}) => ({id, name})),
    });
  });

  /** Find one copied group by its id, full path, or a name only it has. */
  const resolveGroup = Effect.fn("ProjectManagementService.resolveGroup")(
    function*(reference: string, groups: readonly StoredDirectoryGroup[]) {
      const exact = groups.find((group) => group.id === reference || group.path === reference);
      if (exact !== undefined) return exact;
      const named = groups.filter((group) => group.name === reference);
      const only = named.length === 1 ? named[0] : undefined;
      if (only !== undefined) return only;
      return yield* new DirectoryGroupNotFound({
        message: named.length > 1
          ? `Several groups are named ${reference}; use the full path: ${
            named.map((group) => group.path).join(", ")
          }.`
          : `No group matches ${reference}. Use group_list to see the groups.`,
      });
    },
  );

  const sharingOf = Effect.fn("ProjectManagementService.sharingOf")(
    function*(project: ProjectRecord, projectAccess: ProjectAccess) {
      const groups = new Map(
        (yield* access.listDirectoryGroups()).map((group) => [group.id, group]),
      );
      const grants = yield* access.projectSharing.list(project.id);
      const sharing: ProjectSharing = {
        accessMode: projectAccess.mode,
        groups: grants.flatMap((grant) => {
          const group = groups.get(grant.groupId);
          return group === undefined ? [] : [{
            grantedAt: grant.grantedAt,
            groupId: grant.groupId,
            name: group.name,
            path: group.path,
            role: grant.role,
          }];
        }),
        projectId: project.id,
        yourRole: projectAccess.mode === "restricted" ? projectAccess.role : null,
      };
      return sharing;
    },
  );

  /** Any member may create a project, and so may a key that can manage projects. */
  const requireProjectCreation = Effect.fn("ProjectManagementService.requireProjectCreation")(
    function*(principal: Principal) {
      yield* authorization.requireProjectAccess(principal);
      if (
        isDirectHumanPrincipal(principal) ||
        hasCapability(principal, principalCapabilities.manageProjects)
      ) {
        return;
      }
      yield* new AuthorizationDenied({
        message: "Creating a project needs a member session or a key that can manage projects.",
      });
    },
  );

  const createProject = Effect.fn("ProjectManagementService.createProject")(
    function*(command: CreateProjectCommand) {
      yield* requireProjectCreation(command.principal);
      const name = yield* parseProjectName(command.name);
      const shares = command.shareWith ?? [];
      // Resolve every group before anything is written.
      const directory = shares.length === 0 ? [] : yield* access.listDirectoryGroups();
      const grants: {readonly groupId: string; readonly role: ProjectGrantRole}[] = [];
      for (const share of shares) {
        const group = yield* resolveGroup(share.group, directory);
        grants.push({groupId: group.id, role: share.role});
      }
      const createdAt = DateTime.formatIso(yield* dependencies.clock.now);
      const project = yield* dependencies.repository.createProject({
        // New projects are restricted: visible to administrators, the
        // creator, and the groups shared here.
        accessMode: "restricted",
        archivedAt: null,
        createdAt,
        // A service key creates a project with no managing member.
        createdByMemberId: command.principal.kind === principalKinds.human
          ? command.principal.id
          : null,
        id: dependencies.ids.projectId(),
        installationId: dependencies.installationId,
        name,
      });
      // The project exists now, so a share that fails (its group was just
      // removed by directory sync) must not report the whole create as
      // failed: the caller reads the shares that took effect from sharing.
      for (const grant of grants) {
        yield* access.projectSharing.put({
          grantedAt: createdAt,
          grantedByPrincipalId: command.principal.id,
          groupId: grant.groupId,
          projectId: project.id,
          role: grant.role,
        }).pipe(Effect.catchTag("IdentityRepositoryFailure", (failure) =>
          Effect.logWarning(
            `Project ${project.id} was created but not shared with ${grant.groupId}: ${failure.operation}`,
          )
        ));
      }
      yield* Effect.annotateCurrentSpan({"artifact.project.id": project.id});
      return project;
    },
  );

  const getProject = Effect.fn("ProjectManagementService.getProject")(
    function*(command: ReadProjectCommand) {
      return yield* requireProject(
        command.principal,
        command.projectId,
        command.minimumRole,
      );
    },
  );

  const renameProject = Effect.fn("ProjectManagementService.renameProject")(
    function*(command: RenameProjectCommand) {
      yield* requireManagedProject(command.principal, command.projectId);
      return yield* dependencies.repository.renameProject({
        name: yield* parseProjectName(command.name),
        projectId: command.projectId,
      });
    },
  );

  const setProjectArchive = Effect.fn(
    "ProjectManagementService.setProjectArchive",
  )(function*(command: ReadProjectCommand, archivedAt: string | null) {
    const project = yield* requireManagedProject(command.principal, command.projectId);
    const alreadyInRequestedState = archivedAt === null
      ? project.archivedAt === null
      : project.archivedAt !== null;
    if (alreadyInRequestedState) return project;
    return yield* dependencies.repository.setProjectArchive({
      action: archivedAt === null ? "unarchive" : "archive",
      archivedAt,
      actorDisplayName: command.principal.displayName,
      authorizedByPrincipalId: command.principal.authorizedByPrincipalId,
      createdAt: archivedAt ?? DateTime.formatIso(yield* dependencies.clock.now),
      principalId: command.principal.id,
      projectId: command.projectId,
    });
  });

  const archiveProject = Effect.fn("ProjectManagementService.archiveProject")(
    function*(command: ReadProjectCommand) {
      return yield* setProjectArchive(
        command,
        DateTime.formatIso(yield* dependencies.clock.now),
      );
    },
  );

  const unarchiveProject = Effect.fn(
    "ProjectManagementService.unarchiveProject",
  )(function*(command: ReadProjectCommand) {
    return yield* setProjectArchive(command, null);
  });

  const getSharing = Effect.fn("ProjectManagementService.getSharing")(
    function*(command: ReadProjectCommand) {
      const found = yield* requireProjectWithAccess(
        command.principal,
        command.projectId,
        "viewer",
      );
      return yield* sharingOf(found.project, found.access);
    },
  );

  /** Re-read a project's sharing after a manager changed it. */
  const sharingAfterChange = Effect.fn("ProjectManagementService.sharingAfterChange")(
    function*(principal: Principal, project: ProjectRecord) {
      const projectAccess = yield* access.projectAccess(principal, project.id);
      if (projectAccess === null) {
        return yield* new ProjectNotFound({message: "The project does not exist."});
      }
      return yield* sharingOf(project, projectAccess);
    },
  );

  const setAccessMode = Effect.fn("ProjectManagementService.setAccessMode")(
    function*(command: SetProjectAccessCommand) {
      const project = yield* requireManagedProject(command.principal, command.projectId);
      yield* access.projectSharing.setAccessMode(project.id, command.accessMode);
      return yield* sharingAfterChange(command.principal, project);
    },
  );

  const shareWithGroup = Effect.fn("ProjectManagementService.shareWithGroup")(
    function*(command: ShareProjectCommand) {
      const project = yield* requireManagedProject(command.principal, command.projectId);
      const group = yield* resolveGroup(command.group, yield* access.listDirectoryGroups());
      yield* access.projectSharing.put({
        grantedAt: DateTime.formatIso(yield* dependencies.clock.now),
        grantedByPrincipalId: command.principal.id,
        groupId: group.id,
        projectId: project.id,
        role: command.role,
      });
      return yield* sharingAfterChange(command.principal, project);
    },
  );

  const unshareGroup = Effect.fn("ProjectManagementService.unshareGroup")(
    function*(command: UnshareProjectCommand) {
      const project = yield* requireManagedProject(command.principal, command.projectId);
      const group = yield* resolveGroup(command.group, yield* access.listDirectoryGroups());
      yield* access.projectSharing.remove(project.id, group.id);
      return yield* sharingAfterChange(command.principal, project);
    },
  );

  return ProjectManagementService.of({
    archiveProject,
    createProject,
    getProject,
    getSharing,
    setAccessMode,
    shareWithGroup,
    unshareGroup,
    listAuditEvents,
    listProjects,
    listProjectsWithAccess: (principal: Principal) =>
      listVisibleProjects(principal).pipe(
        Effect.map((visible) =>
          visible.map(({access: projectAccess, project}): VisibleProject => ({
            accessMode: projectAccess.mode,
            project,
            yourRole: projectAccess.mode === "restricted" ? projectAccess.role : null,
          }))
        ),
      ),
    renameProject,
    requireManagement: (command: ReadProjectCommand) =>
      requireManagedProject(command.principal, command.projectId),
    ownerCanView: (ownerPrincipalId: string, projectId: string) =>
      access.ownerProjectAccess(ownerPrincipalId, projectId).pipe(
        Effect.map((projectAccess) =>
          projectAccess !== null &&
          (projectAccess.mode === "installation" || projectAccess.role !== null)
        ),
      ),
    resolveActiveProject,
    unarchiveProject,
  });
}

function parseProjectName(
  input: string,
): Effect.Effect<string, InvalidProjectName> {
  return decodeProjectName(input).pipe(
    Effect.mapError(() =>
      new InvalidProjectName({
        message: "Project names must contain between 1 and 120 characters.",
      })
    ),
  );
}
