import {useEffect, useState} from "react";

import {api, type DirectoryGroup} from "@/api/client";
import {ErrorPanel, PageHeader, StatePanel} from "@/components/product";
import {formatTimestamp} from "@/lib/presentation";

/** Read-only list of the Keycloak groups directory sync copies. */
export function GroupsScreen() {
  const [groups, setGroups] = useState<readonly DirectoryGroup[]>([]);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);

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

  useEffect(() => {
    void load();
  }, []);

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        description="Groups and their members are copied from the identity provider by directory sync. Change them there."
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
                  <th className="px-4 py-3 font-semibold">Last synced</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((group) => (
                  <tr className="border-b last:border-b-0" key={group.id}>
                    <td className="px-4 py-4">
                      <p className="font-heading font-semibold">{group.name}</p>
                      <p className="mt-1 text-xs text-muted-foreground">{group.path}</p>
                    </td>
                    <td className="px-4 py-4">{group.memberCount}</td>
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
