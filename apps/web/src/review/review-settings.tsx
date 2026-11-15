import {ArrowLeft01Icon, Moon02Icon, Sun03Icon} from "@hugeicons/core-free-icons";
import {HugeiconsIcon} from "@hugeicons/react";

import {api, isAdministratorRole, organizationPath, type MembershipRole, type Project, type Session} from "@/api/client";
import {StatePanel} from "@/components/product";
import {Button, ButtonLink} from "@/components/ui/button";
import {ArtifactMark} from "./artifact-mark.tsx";
import {parseSettingsRoute, type SettingsRoute} from "./review-routes.ts";
import {ApiKeysScreen} from "./settings-api-keys.tsx";
import {McpScreen} from "./settings-mcp.tsx";
import {GroupsScreen} from "./settings-groups.tsx";
import {MembersScreen} from "./settings-members.tsx";
import {SettingsProject, SettingsProjects} from "./settings-projects.tsx";
import {PublicLinksScreen} from "./settings-public-links.tsx";
import {WebmcpScreen} from "./settings-webmcp.tsx";

interface ReviewSettingsProps {
  readonly onProjectsChanged: () => Promise<readonly Project[]>;
  readonly onThemeChange: () => void;
  readonly projects: readonly Project[];
  readonly session: Session;
  readonly theme: "dawn" | "moon";
}

/** Render project and installation administration inside the canonical application. */
export function ReviewSettings({
  onProjectsChanged,
  onThemeChange,
  projects,
  session,
  theme,
}: ReviewSettingsProps) {
  const route = parseSettingsRoute(window.location.pathname);
  const principal = session.principal;
  const directHuman = principal.kind === "human"
    && principal.authorizedByPrincipalId === null;
  const canManageProjects = directHuman
    || principal.capabilities.includes("project:manage");
  const administrator = directHuman
    && isAdministratorRole(principal.membershipRole);
  const organizationBase = document.querySelector<HTMLMetaElement>('meta[name="as-organization-base"]')?.content ?? "";
  const organizationKind = organizationBase.startsWith("/o/") && organizationBase.replace(/\/+$/u, "") !== "/o/orvex"
    ? "tenant"
    : "installation";
  const tenantDirectory = organizationKind === "tenant";
  const memberDirectoryVisible = tenantDirectory
    ? directHuman && principal.membershipRole === "owner"
    : administrator;
  const reviewHref = readReturnToReview();
  const visiblePages = visibleSettingsPages({
    canManageProjects,
    directHuman,
    organizationKind,
    role: principal.membershipRole,
  });

  return (
    <div className="as-settings">
      <header className="as-settings__header">
        <div className="as-settings__header-inner">
          <a aria-label="Artifact Server" className="as-settings__brand" href={reviewHref}>
            <span className="as-settings__brand-mark">
              <ArtifactMark className="as-settings__mark" />
            </span>
            <span className="as-settings__brand-label">Settings</span>
          </a>
          <div className="as-settings__header-actions">
            <button
              aria-label={theme === "moon" ? "Use light theme" : "Use dark theme"}
              className="as-icon-button"
              onClick={onThemeChange}
              title={theme === "moon" ? "Use light theme" : "Use dark theme"}
              type="button"
            >
              <HugeiconsIcon icon={theme === "moon" ? Sun03Icon : Moon02Icon} strokeWidth={1.8} />
            </button>
            <ButtonLink href={reviewHref} size="sm" variant="outline">
              <HugeiconsIcon data-icon="inline-start" icon={ArrowLeft01Icon} strokeWidth={1.8} />
              Back to review
            </ButtonLink>
            <Button
              onClick={() => void api.logout().finally(() => window.location.assign(organizationPath("/review")))}
              size="sm"
              variant="ghost"
            >
              Sign out
            </Button>
          </div>
        </div>
      </header>
      <div className="as-settings__layout">
        <nav aria-label="Settings" className="as-settings__nav">
          <p>Settings</p>
          {visiblePages.has("projects") ? (
            <SettingsLink active={route.kind === "projects" || route.kind === "project"} href={organizationPath("/review/settings/projects")}>
              Projects
            </SettingsLink>
          ) : null}
          {visiblePages.has("mcp") ? <SettingsLink active={route.kind === "mcp"} href={organizationPath("/review/settings/mcp")}>
            MCP
          </SettingsLink> : null}
          {visiblePages.has("webmcp") ? <SettingsLink active={route.kind === "webmcp"} href={organizationPath("/review/settings/webmcp")}>
            WebMCP
          </SettingsLink> : null}
          {visiblePages.has("groups") ? (
            <SettingsLink active={route.kind === "groups"} href={organizationPath("/review/settings/groups")}>Groups</SettingsLink>
          ) : null}
          {visiblePages.has("members") ? <SettingsLink active={route.kind === "members"} href={organizationPath("/review/settings/members")}>Members</SettingsLink> : null}
          {visiblePages.has("apiKeys") && visiblePages.has("publicLinks") ? (
            <>
              <SettingsLink active={route.kind === "apiKeys"} href={organizationPath("/review/settings/api-keys")}>API keys</SettingsLink>
              <SettingsLink active={route.kind === "publicLinks"} href={organizationPath("/review/settings/public-links")}>Public links</SettingsLink>
            </>
          ) : null}
        </nav>
        <main className="as-settings__content" id="main-content">
          <SettingsContent
            administrator={administrator}
            canManageProjects={canManageProjects}
            memberDirectoryVisible={memberDirectoryVisible}
            onProjectsChanged={onProjectsChanged}
            projects={projects}
            route={route}
            session={session}
          />
        </main>
      </div>
    </div>
  );
}

function SettingsContent({
  administrator,
  canManageProjects,
  memberDirectoryVisible,
  onProjectsChanged,
  projects,
  route,
  session,
}: {
  readonly administrator: boolean;
  readonly canManageProjects: boolean;
  readonly memberDirectoryVisible: boolean;
  readonly onProjectsChanged: () => Promise<readonly Project[]>;
  readonly projects: readonly Project[];
  readonly route: SettingsRoute;
  readonly session: Session;
}) {
  const principal = session.principal;
  const directHuman = principal.kind === "human" && principal.authorizedByPrincipalId === null;
  const organizationBase = document.querySelector<HTMLMetaElement>('meta[name="as-organization-base"]')?.content ?? "";
  const tenantDirectory = organizationBase.startsWith("/o/") && organizationBase.replace(/\/+$/u, "") !== "/o/orvex";
  if (route.kind === "notFound") {
    return (
      <StatePanel
        action={(
          <ButtonLink href={organizationPath("/review/settings/projects")} variant="outline">
            View settings
          </ButtonLink>
        )}
        description="This Artifact Server settings route does not exist."
        title="Page not found"
      />
    );
  }
  if (route.kind === "projects" || route.kind === "project") {
    if (!canManageProjects) return <ProjectPermissionRequired />;
    if (route.kind === "projects") {
      return (
        <SettingsProjects
          canManage={canManageProjects}
          gitHistory={session.capabilities.gitHistory}
          onProjectsChanged={onProjectsChanged}
          projects={projects}
        />
      );
    }
    return (
      <SettingsProject
        administrator={administrator}
        canManage={canManageProjects}
        gitHistory={session.capabilities.gitHistory}
        onProjectsChanged={onProjectsChanged}
        projectId={route.projectId}
        projects={projects}
      />
    );
  }
  if (principal.membershipRole === "guest") return <AdministratorPermissionRequired />;
  if (route.kind === "mcp") return <McpScreen administrator={administrator} />;
  if (route.kind === "webmcp") return <WebmcpScreen />;
  if (route.kind === "groups") {
    return <GroupsScreen canEdit={directHuman && (tenantDirectory
      ? principal.membershipRole === "owner"
      : isAdministratorRole(principal.membershipRole))} />;
  }
  if (route.kind === "members" && memberDirectoryVisible) {
    return (
      <MembersScreen
        canAdmit={!tenantDirectory}
        canManage={administrator}
        showEmails={principal.membershipRole === "member" || principal.membershipRole === "owner"}
        showRoles={administrator}
      />
    );
  }
  if (!administrator) return <AdministratorPermissionRequired />;
  switch (route.kind) {
    case "members":
      return <AdministratorPermissionRequired />;
    case "apiKeys":
      return <ApiKeysScreen />;
    case "publicLinks":
      return <PublicLinksScreen />;
  }
  return <AdministratorPermissionRequired />;
}

function SettingsLink({
  active,
  children,
  href,
}: {
  readonly active: boolean;
  readonly children: React.ReactNode;
  readonly href: string;
}) {
  return (
    <a aria-current={active ? "page" : undefined} data-active={active} href={href}>
      {children}
    </a>
  );
}

function ProjectPermissionRequired() {
  return (
    <StatePanel
      description="This account cannot manage projects."
      title="Project permission required"
    />
  );
}

function AdministratorPermissionRequired() {
  return (
    <StatePanel
      description="Only an installation administrator can manage members, API keys, and public links."
      title="Administrator permission required"
    />
  );
}

function readReturnToReview(): string {
  const stored = window.sessionStorage.getItem("artifact-review-return-url");
  return stored?.startsWith("/review") && !stored.startsWith("/review/settings")
    ? organizationPath(stored)
    : organizationPath("/review");
}

type SettingsPage = "apiKeys" | "groups" | "members" | "mcp" | "projects" | "publicLinks" | "webmcp";
type OrganizationKind = "installation" | "tenant";

/** The client-visible settings surface mirrors authorization already known by the current session. */
export function visibleSettingsPages({
  canManageProjects,
  directHuman,
  organizationKind,
  role,
}: {
  readonly canManageProjects: boolean;
  readonly directHuman: boolean;
  readonly organizationKind: OrganizationKind;
  readonly role: MembershipRole;
}): ReadonlySet<SettingsPage> {
  const pages = new Set<SettingsPage>();
  const administrator = directHuman && isAdministratorRole(role);
  if (canManageProjects) pages.add("projects");
  if (role !== "guest") {
    pages.add("mcp");
    pages.add("webmcp");
    pages.add("groups");
  }
  if (
    organizationKind === "tenant"
      ? directHuman && role === "owner"
      : administrator
  ) {
    pages.add("members");
  }
  if (administrator) {
    pages.add("apiKeys");
    pages.add("publicLinks");
  }
  return pages;
}
