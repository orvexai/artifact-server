import {useEffect, useState} from "react";

import {
  api,
  type DirectoryGroup,
  type ProjectGrantRole,
  type ProjectSharing,
} from "@/api/client";
import {StatusBadge} from "@/components/product";
import {Button} from "@/components/ui/button";
import {Label} from "@/components/ui/label";
import {NativeSelect, NativeSelectOption} from "@/components/ui/native-select";

const roleLabels = {
  editor: "Editor: also publishes and manages artifacts",
  manager: "Manager: also renames, archives and shares",
  viewer: "Viewer: reads and comments",
} as const satisfies Readonly<Record<ProjectGrantRole, string>>;

/** Who may see one project; its managers can restrict, open and share it. */
export function ProjectSharingSection({
  administrator,
  projectId,
}: {
  readonly administrator: boolean;
  readonly projectId: string;
}) {
  const [sharing, setSharing] = useState<ProjectSharing | null>(null);
  const [groups, setGroups] = useState<readonly DirectoryGroup[]>([]);
  const [groupId, setGroupId] = useState("");
  const [role, setRole] = useState<ProjectGrantRole>("viewer");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let current = true;
    void (async (): Promise<void> => {
      try {
        const [loaded, directory] = await Promise.all([
          api.projectSharing(projectId),
          api.groups(),
        ]);
        if (!current) return;
        setSharing(loaded);
        setGroups(directory);
      } catch (caught) {
        if (current) {
          setError(caught instanceof Error ? caught.message : "Sharing could not be loaded.");
        }
      }
    })();
    return () => {
      current = false;
    };
  }, [projectId]);

  const change = async (run: () => Promise<ProjectSharing>, failure: string) => {
    setPending(true);
    setError(null);
    try {
      setSharing(await run());
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : failure);
    } finally {
      setPending(false);
    }
  };

  // The server's rule: an open project is managed by administrators; a
  // restricted one also by its own managers.
  const canManage = sharing !== null && (
    administrator || sharing.yourRole === "manager" || sharing.yourRole === "administrator"
  );
  const restricted = sharing?.accessMode === "restricted";
  const sharedIds = new Set(sharing?.groups.map((group) => group.groupId) ?? []);
  const available = groups.filter((group) => !sharedIds.has(group.id));

  return (
    <section className="grid gap-5 border p-5 sm:p-6" aria-labelledby="project-sharing-heading">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="font-heading text-lg font-semibold" id="project-sharing-heading">
            Who can see this project
          </h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-muted-foreground">
            {restricted
              ? "Only administrators, the project's creator, and the groups below can see it."
              : "Every member can see it. Restrict it to share it with chosen groups only."}
          </p>
        </div>
        <StatusBadge tone={restricted ? "primary" : "neutral"}>
          {sharing === null ? "Loading" : restricted ? "Restricted" : "Every member"}
        </StatusBadge>
      </div>

      {error === null ? null : <p className="text-sm text-destructive" role="alert">{error}</p>}

      {sharing === null ? null : (
        <>
          <div>
            <Button
              disabled={!canManage || pending}
              onClick={() => void change(
                () => api.setProjectAccess(projectId, restricted ? "installation" : "restricted"),
                "The project's access could not be changed.",
              )}
              type="button"
              variant="outline"
            >
              {restricted ? "Open to every member" : "Restrict to shared groups"}
            </Button>
          </div>

          {sharing.groups.length === 0 ? (
            <p className="text-sm text-muted-foreground">Not shared with any group yet.</p>
          ) : (
            <ul className="grid gap-2">
              {sharing.groups.map((group) => (
                <li className="flex flex-wrap items-center justify-between gap-3 border p-3" key={group.groupId}>
                  <div>
                    <p className="font-heading font-semibold">{group.name}</p>
                    <p className="text-xs text-muted-foreground">{group.path} · {group.role}</p>
                  </div>
                  <Button
                    disabled={!canManage || pending}
                    onClick={() => void change(
                      () => api.unshareProject(projectId, group.groupId),
                      "The group could not be removed.",
                    )}
                    size="xs"
                    type="button"
                    variant="ghost"
                  >
                    Remove
                  </Button>
                </li>
              ))}
            </ul>
          )}

          {canManage ? (
            <div className="grid max-w-2xl gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end">
              <div className="grid gap-2">
                <Label htmlFor="project-share-group">Group</Label>
                <NativeSelect
                  disabled={pending}
                  id="project-share-group"
                  onChange={(event) => setGroupId(event.currentTarget.value)}
                  value={groupId}
                >
                  <NativeSelectOption value="">Choose a group</NativeSelectOption>
                  {available.map((group) => (
                    <NativeSelectOption key={group.id} value={group.id}>{group.path}</NativeSelectOption>
                  ))}
                </NativeSelect>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="project-share-role">Role</Label>
                <NativeSelect
                  disabled={pending}
                  id="project-share-role"
                  onChange={(event) => setRole(projectGrantRole(event.currentTarget.value))}
                  value={role}
                >
                  {(["viewer", "editor", "manager"] as const).map((option) => (
                    <NativeSelectOption key={option} value={option}>{roleLabels[option]}</NativeSelectOption>
                  ))}
                </NativeSelect>
              </div>
              <Button
                disabled={pending || groupId === ""}
                onClick={() => void change(async () => {
                  const updated = await api.shareProject(projectId, groupId, role);
                  setGroupId("");
                  return updated;
                }, "The project could not be shared.")}
                type="button"
              >
                Share
              </Button>
            </div>
          ) : null}
        </>
      )}
    </section>
  );
}

function projectGrantRole(value: string): ProjectGrantRole {
  return value === "editor" || value === "manager" ? value : "viewer";
}
