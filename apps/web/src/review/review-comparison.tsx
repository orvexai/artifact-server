import type {ComparedFile, TextLineChange} from "@/api/client";
import {formatBytes} from "@/lib/presentation";

/**
 * A changed file can carry up to 256 KiB of text on each side, and an edit
 * distance past the server's bound collapses into one whole-file region. The
 * inspector is a narrow side panel, so it paints a bounded number of lines
 * and says how many it left out instead of freezing on a huge replacement.
 */
const maximumRenderedLines = 400;

interface DiffLine {
  readonly kind: "added" | "removed";
  readonly number: number;
  readonly text: string;
}

interface DiffHunk {
  readonly header: string;
  readonly key: string;
  readonly lines: readonly DiffLine[];
}

interface LineChangeTotals {
  readonly added: number;
  readonly removed: number;
}

interface BoundedHunks {
  readonly hidden: number;
  readonly hunks: readonly DiffHunk[];
}

/** Count the lines one comparison adds and removes across its regions. */
function lineChangeTotals(changes: readonly TextLineChange[]): LineChangeTotals {
  let added = 0;
  let removed = 0;
  for (const change of changes) {
    added += change.after.length;
    removed += change.before.length;
  }
  return {added, removed};
}

function hunkLines(change: TextLineChange): readonly DiffLine[] {
  return [
    ...change.before.map((text, index) => ({
      kind: "removed" as const,
      number: change.beforeStartLine + index,
      text,
    })),
    ...change.after.map((text, index) => ({
      kind: "added" as const,
      number: change.afterStartLine + index,
      text,
    })),
  ];
}

function boundedHunks(changes: readonly TextLineChange[]): BoundedHunks {
  const hunks: DiffHunk[] = [];
  let budget = maximumRenderedLines;
  let hidden = 0;
  for (const change of changes) {
    const lines = hunkLines(change);
    const shown = lines.slice(0, Math.max(budget, 0));
    hidden += lines.length - shown.length;
    budget -= shown.length;
    if (shown.length === 0) continue;
    hunks.push({
      header: `@@ −${change.beforeStartLine},${change.before.length} +${change.afterStartLine},${change.after.length} @@`,
      key: `${change.beforeStartLine}:${change.afterStartLine}`,
      lines: shown,
    });
  }
  return {hidden, hunks};
}

/** The bounded line view of one same-path changed file in Compare. */
export function ComparedFileLines({file}: {readonly file: ComparedFile}) {
  const detail = file.detail;
  if (detail.kind === "binary") {
    return (
      <p className="as-diff__note">
        {detail.reason === "text_limit_exceeded"
          ? "Too large for a line comparison"
          : "Binary or non-UTF-8 content"}
        {` · ${formatBytes(file.before.size)} → ${formatBytes(file.after.size)}`}
      </p>
    );
  }
  const totals = lineChangeTotals(detail.changes);
  if (detail.changes.length === 0) {
    return <p className="as-diff__note">Only the fingerprint changed; every line matches.</p>;
  }
  const {hidden, hunks} = boundedHunks(detail.changes);
  return (
    <div aria-label={`Line changes in ${file.after.path}`} className="as-diff" role="group">
      <p className="as-diff__stats">
        <span data-kind="added">+{totals.added}</span>
        <span data-kind="removed">−{totals.removed}</span>
        <span>
          {detail.changes.length} {detail.changes.length === 1 ? "region" : "regions"}
          {` · ${detail.beforeLineCount} → ${detail.afterLineCount} lines`}
        </span>
      </p>
      {hunks.map((hunk) => (
        <div className="as-diff__hunk" key={hunk.key}>
          <div aria-hidden="true" className="as-diff__header">{hunk.header}</div>
          {hunk.lines.map((line) => (
            <div
              className="as-diff__line"
              data-kind={line.kind}
              key={`${line.kind}:${line.number}`}
            >
              <span aria-hidden="true" className="as-diff__number">{line.number}</span>
              <span className="as-diff__marker">
                <span aria-hidden="true">{line.kind === "added" ? "+" : "−"}</span>
                <span className="as-visually-hidden">
                  {line.kind === "added" ? `Added line ${line.number}: ` : `Removed line ${line.number}: `}
                </span>
              </span>
              <code>{line.text === "" ? " " : line.text}</code>
            </div>
          ))}
        </div>
      ))}
      {hidden === 0 ? null : (
        <p className="as-diff__note">
          {hidden} more changed {hidden === 1 ? "line is" : "lines are"} not shown here.
        </p>
      )}
    </div>
  );
}
