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
    if (group.source === "rule" && value === "none" &&
      !window.confirm("Removing this rule role means members of this group will lose access. Continue?")) return;
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
        ? <StatePanel description="Loading directory groups." loading title="Loading groups" />
        : groups.length === 0
        ? (
          <StatePanel
            description="Directory sync has not copied any groups yet."
            title="No groups"
          />
        )
        : (
          <div className="as-groups-inventory" id="settings-groups-table">
            <table
              aria-label="Groups"
              className="as-groups-table w-full text-left text-sm"
              role="table"
            >
              <thead
                className="border-b bg-muted/50 text-xs tracking-widest text-muted-foreground uppercase"
                role="rowgroup"
              >
                <tr role="row">
                  <th className="px-4 py-3 font-semibold" role="columnheader">Group</th>
                  <th className="px-4 py-3 font-semibold" role="columnheader">Members</th>
                  <th className="px-4 py-3 font-semibold" role="columnheader">Role</th>
                  <th className="px-4 py-3 font-semibold" role="columnheader">Last synced</th>
                </tr>
              </thead>
              <tbody role="rowgroup">
                {groups.map((group) => (
                  <tr className="as-groups-table__row" key={group.id} role="row">
                    <td className="as-groups-table__group px-4 py-4" role="cell">
                      <p className="font-heading font-semibold">{group.name}</p>
                      <p className="mt-1 text-xs text-muted-foreground">{group.path}</p>
                      {group.role === "guest" && group.hasHigherRoleOverlap
                        ? <p className="mt-2 text-xs text-amber-700">Some members also belong to a group with a higher installation role. Admin and Owner roles take precedence over Guest.</p>
                        : null}
                    </td>
                    <td className="as-groups-table__members px-4 py-4" role="cell">
                      <span className="as-groups-table__label">Members</span>
                      {group.memberCount}
                    </td>
                    <td className="as-groups-table__role px-4 py-4" role="cell">
                      {canEdit
                        ? <select className="min-w-32 rounded border border-input bg-background px-2 py-1 text-foreground" aria-label={`Role for ${group.name}`} disabled={pending === group.id} onChange={(event) => void setRole(group, event.target.value)} value={group.role === "member" ? "operator" : group.role === "administrator" ? "admin" : group.role ?? "none"}>
                            <option className="bg-background text-foreground" value="none">None</option>
                            {(["guest", "viewer", "operator", "admin", "owner"] as const).map((role) => <option className="bg-background text-foreground" key={role} value={role}>{role === "admin" ? membershipRoleLabels.administrator : role === "operator" ? membershipRoleLabels.member : membershipRoleLabels[role]}{group.source === "rule" && role === "guest" ? " (rule)" : ""}</option>)}
                          </select>
                        : group.role === null || group.role === undefined ? "None" : `${membershipRoleLabels[group.role]}${group.source === "rule" ? " (rule)" : ""}`}
                    </td>
                    <td
                      className="as-groups-table__synced px-4 py-4 whitespace-nowrap text-muted-foreground"
                      role="cell"
                    >
                      <span className="as-groups-table__label">Last synced</span>
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
