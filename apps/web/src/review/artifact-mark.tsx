/** Houston Brand and Design System v0.4.0 Mark D. */
export function ArtifactMark({className}: {readonly className?: string}) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="none"
      viewBox="0 0 48 48"
    >
      <rect height="43.5" rx="10.75" stroke="var(--ox-color-text)" strokeWidth="4.5" width="43.5" x="2.25" y="2.25" />
      <circle cx="24" cy="24" r="12.75" stroke="var(--ox-color-text)" strokeWidth="4.5" />
      <circle cx="15" cy="33" r="6" fill="var(--ox-color-accent)" />
    </svg>
  );
}
