/** Houston's radar-scope mark, using the micro cut below 24px. */
export function ArtifactMark({className}: {readonly className?: string}) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="none"
      viewBox="0 0 48 48"
    >
      <rect height="41.2" rx="9.6" stroke="currentColor" strokeWidth="6.8" width="41.2" x="3.4" y="3.4" />
      <circle cx="24" cy="24" r="13" stroke="currentColor" strokeWidth="1.8" />
      <circle cx="24" cy="24" r="7" stroke="currentColor" strokeWidth="1.8" />
      <path d="M24 24 33.192 14.808" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" />
      <circle cx="24" cy="24" r="1.2" fill="currentColor" />
      <circle cx="14.808" cy="33.192" r="3" fill="#0891b2" />
    </svg>
  );
}
