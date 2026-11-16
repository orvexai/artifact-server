/** Houston's radar-scope mark, using the micro cut below 24px. */
export function ArtifactMark({className}: {readonly className?: string}) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="none"
      viewBox="0 0 16 16"
    >
      <rect height="14" rx="4" stroke="currentColor" strokeWidth="2" width="14" x="1" y="1" />
      <circle cx="8" cy="8" r="4.5" stroke="currentColor" strokeWidth="1" />
      <circle cx="8" cy="8" r="1" fill="currentColor" />
      <circle cx="4.818" cy="11.182" r="1.8" fill="#0891b2" />
    </svg>
  );
}
