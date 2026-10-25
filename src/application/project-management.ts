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
  type ProjectRole,
  projectRoleAtLeast,
} from "../core/project-access.js";
import type {ProjectAuditEvent, ProjectRecord} from "../core/model.js";
import type {
  CreateProject,
  IdGenerator,
  RenameProject,
  SetProjectArchive,
} from "../core/ports.js";

const projectNameSchema = Schema.Trim.check(Schema.isLengthBetween(1, 120));
const decodeProjectName = Schema.decodeUnknownEffect(projectNameSchema);

/** Input for creating one project inside the current installation. */
export interface CreateProjectCommand {
  readonly name: string;
  readonly principal: Principal;
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
  readonly getProject: (
    command: ReadProjectCommand,
  ) => Effect.Effect<ProjectRecord, ProjectManagementFailure>;
  readonly listProjects: (
    principal: Principal,
  ) => Effect.Effect<readonly ProjectRecord[], ProjectManagementFailure>;
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

  const createProject = Effect.fn("ProjectManagementService.createProject")(
    function*(command: CreateProjectCommand) {
      yield* authorization.requireProjectManagement(command.principal);
      const name = yield* parseProjectName(command.name);
      const project = yield* dependencies.repository.createProject({
        archivedAt: null,
        createdAt: DateTime.formatIso(yield* dependencies.clock.now),
        // A service key creates a project with no managing member.
        createdByMemberId: command.principal.kind === principalKinds.human
          ? command.principal.id
          : null,
        id: dependencies.ids.projectId(),
        installationId: dependencies.installationId,
        name,
      });
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

  return ProjectManagementService.of({
    archiveProject,
    createProject,
    getProject,
    listAuditEvents,
    listProjects,
    renameProject,
    requireManagement: (command: ReadProjectCommand) =>
      requireManagedProject(command.principal, command.projectId),
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
