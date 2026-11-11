import {useEffect, useState} from "react";

import {api, membershipRoleLabels, type DirectoryGroup} from "@/api/client";
import {ErrorPanel, PageHeader, StatePanel} from "@/components/product";
import {formatTimestamp} from "@/lib/presentation";

/** List copied directory groups and allow installation owners to assign roles. */
export function GroupsScreen({canEdit}: {readonly canEdit: boolean}) {
  const [groups, setGroups] = useState<readonly DirectoryGroup[]>([]);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);
  const [pending, setPending] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      setGroups(await api.groups());
    } catch (caught) {
      setError(caught instanceof Error ? caught : new Error("Group list failed."));
    } finally {
      setLoading(false);
    }
  };

  const setRole = async (group: DirectoryGroup, value: string) => {
    setPending(group.id);
    try {
      const role = value === "none" ? null
        : value === "admin" || value === "guest" || value === "operator" || value === "owner" || value === "viewer"
        ? value
        : null;
      if (value !== "none" && role === null) throw new Error("Unknown group role.");
      await api.setGroupRole(group.id, role);
      await load();
    } catch (caught) {
      setError(caught instanceof Error ? caught : new Error("Group role update failed."));
    } finally {
      setPending(null);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        description="Groups and their members are copied from the identity provider by directory sync. Assign installation roles here."
        eyebrow="Administration"
        title="Groups"
      />

      {error === null ? null : <ErrorPanel error={error} onRetry={() => void load()} />}
      {loading && groups.length === 0
        ? <StatePanel description="Loading directory groups." title="Loading groups" />
        : groups.length === 0
        ? (
          <StatePanel
            description="Directory sync has not copied any groups yet."
            title="No groups"
          />
        )
        : (
          <div className="overflow-x-auto border">
            <table className="w-full min-w-3xl text-left text-sm">
              <thead className="border-b bg-muted/50 text-xs tracking-widest text-muted-foreground uppercase">
                <tr>
                  <th className="px-4 py-3 font-semibold">Group</th>
                  <th className="px-4 py-3 font-semibold">Members</th>
                  <th className="px-4 py-3 font-semibold">Role</th>
                  <th className="px-4 py-3 font-semibold">Last synced</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((group) => (
                  <tr className="border-b last:border-b-0" key={group.id}>
                    <td className="px-4 py-4">
                      <p className="font-heading font-semibold">{group.name}</p>
                      <p className="mt-1 text-xs text-muted-foreground">{group.path}</p>
                      {group.role === "guest" && group.hasHigherRoleOverlap
                        ? <p className="mt-2 text-xs text-amber-700">Some members also belong to a group with a higher installation role. Admin and Owner roles take precedence over Guest.</p>
                        : null}
                    </td>
                    <td className="px-4 py-4">{group.memberCount}</td>
                    <td className="px-4 py-4">
                      {canEdit
                        ? <select aria-label={`Role for ${group.name}`} disabled={pending === group.id} onChange={(event) => void setRole(group, event.target.value)} value={group.role === "member" ? "operator" : group.role === "administrator" ? "admin" : group.role ?? "none"}>
                            <option value="none">None</option>
                            {(["guest", "viewer", "operator", "admin", "owner"] as const).map((role) => <option key={role} value={role}>{role === "admin" ? membershipRoleLabels.administrator : role === "operator" ? membershipRoleLabels.member : membershipRoleLabels[role]}</option>)}
                          </select>
                        : group.role === null ? "None" : `${membershipRoleLabels[group.role]}${group.source === "rule" ? " (rule)" : ""}`}
                      {canEdit && group.source === "rule" ? <span className="ml-2 text-xs text-muted-foreground">(rule)</span> : null}
                    </td>
                    <td className="px-4 py-4 whitespace-nowrap text-muted-foreground">
                      {formatTimestamp(group.syncedAt)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
    </div>
  );
}
