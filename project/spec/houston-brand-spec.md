# brand-source

The Houston brand tokens and contrast proof are vendored from the `design-system` directory in `orvexai/houston` at commit `524b0137e3a3fae6ea0e991202bcf90323412a74` (Houston Brand and Design System v0.4.0); vendored design-system files are byte copies of that pinned source.

# brand-contrast

All 62 Houston design-system contrast pairs, together with the local `accent-text-strong`, `danger-hover`, and `destructive` tokens, meet the text contrast ratio of 4.5:1 and non-text contrast ratio of 3:1 in both light and dark themes.

# brand-mark

Every product mark surface uses Mark D, and the favicon and app-icon files are byte-identical to the corresponding Houston Brand and Design System v0.4.0 files.

# brand-mark-theme

Wherever Mark D renders, its dot uses the theme accent (`#0891b2` in light theme and `#23b5d1` in dark theme), while its frame and ring use the theme text colour.

# brand-loader

Every loader has an accessible name and the right role, shows no rotation under reduced motion, and needs no content security policy change.

# brand-naming

No user-visible Artifact Server or Orvex product string appears in the scanned surfaces outside brand-naming-allowlist.json; Orvex as an organization name is allowlisted.

# brand-compat

The CLI binary, environment names, MCP server and tool names, and cookie names retain their established compatibility names.

# brand-identity

The MCP serverInfo title, OAuth resource_name and DCR client_name read Houston Artifacts; the client id, server name and scope are unchanged.

# brand-assets

Shipped assets under apps/web/public and apps/web/src/brand contain no violet or indigo values.
