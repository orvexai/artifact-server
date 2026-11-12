/** MCP tools exposed to explicitly configured OIDC project provisioners. */
export const provisionerToolAllowList: ReadonlySet<string> = new Set([
  "project_list",
  "project_create",
  "project_sharing",
  "project_share",
  "project_set_access",
]);

export const provisionerToolNames = [...provisionerToolAllowList] as const;
