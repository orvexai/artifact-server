import { Context, Effect, Layer } from "effect";

import {
  type AuthorizationOperations,
  AuthorizationService,
} from "./authorization.js";
import {
  type ProjectManagementFailure,
  ProjectManagementService,
} from "./project-management.js";
import {
  ArtifactNotFound,
  type ArtifactRepositoryFailure,
  type AuthorizationDenied,
  type BlobStorageFailure,
  VersionNotFound,
} from "../core/errors.js";
import type { Principal } from "../core/identity.js";
import type {
  ArtifactRecord,
  ArtifactVersion,
  ManifestEntry,
  VersionRecord,
} from "../core/model.js";
import {
  compareManifests,
  type ManifestChange,
  type ManifestRename,
} from "../comparison/compare-manifests.js";

const maximumTextDiffBytes = 256 * 1_024;

/** Input for comparing two saved versions of one artifact. */
export interface CompareArtifactVersionsCommand {
  readonly artifactId: string;
  readonly fromVersionId: string;
  readonly principal: Principal;
  readonly projectId: string | null;
  readonly toVersionId: string;
}

/** One bounded line-level replacement region. */
export interface TextLineChange {
  readonly after: readonly string[];
  readonly afterStartLine: number;
  readonly before: readonly string[];
  readonly beforeStartLine: number;
}

/** Safe comparison detail for one changed same-path file. */
export type FileComparisonDetail =
  | {
    readonly afterLineCount: number;
    readonly beforeLineCount: number;
    readonly changes: readonly TextLineChange[];
    readonly kind: "text";
  }
  | {
    readonly kind: "binary";
    readonly reason: "binary_or_invalid_utf8" | "text_limit_exceeded";
  };

/** One changed file and its bounded comparison detail. */
export interface ComparedFileChange extends ManifestChange {
  readonly detail: FileComparisonDetail;
}

/** Authenticated comparison of two immutable saved versions. */
export interface ArtifactComparison {
  readonly added: readonly ManifestEntry[];
  readonly artifact: ArtifactRecord;
  readonly changed: readonly ComparedFileChange[];
  readonly from: VersionRecord;
  readonly removed: readonly ManifestEntry[];
  readonly renamed: readonly ManifestRename[];
  readonly to: VersionRecord;
  readonly unchangedCount: number;
}

/** Persistence required to obtain comparison inputs. */
export interface CompareArtifactRepository {
  readonly findArtifact: (
    projectId: string,
    artifactId: string,
  ) => Effect.Effect<ArtifactRecord | null, ArtifactRepositoryFailure>;
  readonly findVersionRecord: (
    projectId: string,
    artifactId: string,
    versionId: string,
  ) => Effect.Effect<ArtifactVersion | null, ArtifactRepositoryFailure>;
}

/** Immutable byte reads required for bounded text comparison. */
export interface ComparisonBlobStorage {
  readonly readBytes: (
    entry: ManifestEntry,
  ) => Effect.Effect<Uint8Array, BlobStorageFailure>;
}

/** Dependencies used to construct comparison operations. */
export interface CompareArtifactDependencies {
  readonly blobs: ComparisonBlobStorage;
  readonly repository: CompareArtifactRepository;
}

/** Expected failures produced by version comparison. */
export type CompareArtifactFailure =
  | ArtifactNotFound
  | VersionNotFound
  | AuthorizationDenied
  | ArtifactRepositoryFailure
  | BlobStorageFailure
  | ProjectManagementFailure;

interface CompareArtifactOperations {
  readonly compareVersions: (
    command: CompareArtifactVersionsCommand,
  ) => Effect.Effect<ArtifactComparison, CompareArtifactFailure>;
}

/** Compares primary manifests and bounded text without requiring Git. */
export class CompareArtifactService extends Context.Service<
  CompareArtifactService,
  CompareArtifactOperations
>()("artifact-server/application/CompareArtifactService") {
  /** Construct comparison from deployment-neutral records and blob reads. */
  static readonly layer = (
    dependencies: CompareArtifactDependencies,
  ): Layer.Layer<
    CompareArtifactService,
    never,
    AuthorizationService | ProjectManagementService
  > =>
    Layer.effect(
      CompareArtifactService,
      Effect.gen(function*() {
        const authorization = yield* AuthorizationService;
        const projects = yield* ProjectManagementService;
        return makeCompareArtifactService(dependencies, authorization, projects);
      }),
    );
}

function makeCompareArtifactService(
  dependencies: CompareArtifactDependencies,
  authorization: AuthorizationOperations,
  projects: ProjectManagementService["Service"],
): CompareArtifactOperations {
  const requireVersion = Effect.fn("CompareArtifactService.requireVersion")(
    function*(projectId: string, artifactId: string, versionId: string) {
      const version = yield* dependencies.repository.findVersionRecord(
        projectId,
        artifactId,
        versionId,
      );
      if (version !== null) return version;
      return yield* new VersionNotFound({
        message: "The saved version does not exist on this artifact.",
      });
    },
  );

  const compareChangedFile = Effect.fn("CompareArtifactService.compareChangedFile")(
    function*(change: ManifestChange) {
      if (!isTextMediaType(change.before.mediaType) ||
        !isTextMediaType(change.after.mediaType)) {
        return comparedBinary(change, "binary_or_invalid_utf8");
      }
      if (
        change.before.size > maximumTextDiffBytes ||
        change.after.size > maximumTextDiffBytes
      ) {
        return comparedBinary(change, "text_limit_exceeded");
      }
      const [beforeBytes, afterBytes] = yield* Effect.all([
        dependencies.blobs.readBytes(change.before),
        dependencies.blobs.readBytes(change.after),
      ], {concurrency: 2});
      const beforeText = decodeUtf8(beforeBytes);
      const afterText = decodeUtf8(afterBytes);
      if (beforeText === null || afterText === null) {
        return comparedBinary(change, "binary_or_invalid_utf8");
      }
      const beforeLines = splitLines(beforeText);
      const afterLines = splitLines(afterText);
      return {
        ...change,
        detail: {
          afterLineCount: afterLines.length,
          beforeLineCount: beforeLines.length,
          changes: changedLineRegions(beforeLines, afterLines),
          kind: "text" as const,
        },
      };
    },
  );

  const compareVersions = Effect.fn("CompareArtifactService.compareVersions")(
    function*(command: CompareArtifactVersionsCommand) {
      const project = command.projectId === null
        ? yield* projects.resolveActiveProject({
          principal: command.principal,
          projectId: null,
        })
        : yield* projects.getProject({
          principal: command.principal,
          projectId: command.projectId,
        });
      const artifact = yield* dependencies.repository.findArtifact(
        project.id,
        command.artifactId,
      );
      if (artifact === null) {
        return yield* new ArtifactNotFound({
          message: "The artifact does not exist.",
        });
      }
      yield* authorization.requireArtifactRead(command.principal);
      const [from, to] = yield* Effect.all([
        requireVersion(project.id, artifact.id, command.fromVersionId),
        requireVersion(project.id, artifact.id, command.toVersionId),
      ], {concurrency: 2});
      const structural = compareManifests(from.manifest, to.manifest);
      const changed = yield* Effect.forEach(
        structural.changed,
        compareChangedFile,
        {concurrency: 1},
      );
      return {
        added: structural.added,
        artifact,
        changed,
        from: from.version,
        removed: structural.removed,
        renamed: structural.renamed,
        to: to.version,
        unchangedCount: structural.unchanged.length,
      };
    },
  );

  return CompareArtifactService.of({compareVersions});
}

function comparedBinary(
  change: ManifestChange,
  reason: Extract<FileComparisonDetail, {readonly kind: "binary"}>["reason"],
): ComparedFileChange {
  return {...change, detail: {kind: "binary", reason}};
}

function decodeUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", {fatal: true}).decode(bytes);
  } catch {
    return null;
  }
}

function isTextMediaType(mediaType: string): boolean {
  const essence = mediaType.split(";", 1)[0]?.trim().toLocaleLowerCase("en-US");
  return essence?.startsWith("text/") === true ||
    essence === "application/javascript" ||
    essence === "application/json" ||
    essence === "application/xml" ||
    essence === "application/xhtml+xml" ||
    essence === "image/svg+xml";
}

function splitLines(text: string): readonly string[] {
  return text.split("\n");
}

function changedLineRegions(
  before: readonly string[],
  after: readonly string[],
): readonly TextLineChange[] {
  const maxEditDistance = 512;
  let frontier = new Map<number, number>([[1, 0]]);
  const trace: Map<number, number>[] = [];
  let distance = 0;
  let finished = false;

  for (distance = 0; distance <= maxEditDistance; distance += 1) {
    trace.push(new Map(frontier));
    for (let diagonal = -distance; diagonal <= distance; diagonal += 2) {
      const previousX = diagonal === -distance ||
          (diagonal !== distance &&
            (frontier.get(diagonal - 1) ?? -1) <
              (frontier.get(diagonal + 1) ?? -1))
        ? frontier.get(diagonal + 1) ?? 0
        : (frontier.get(diagonal - 1) ?? 0) + 1;
      let x = previousX;
      let y = x - diagonal;
      while (x < before.length && y < after.length && before[x] === after[y]) {
        x += 1;
        y += 1;
      }
      frontier.set(diagonal, x);
      if (x >= before.length && y >= after.length) {
        finished = true;
        break;
      }
    }
    if (finished) break;
  }

  if (!finished) return [wholeFileChange(before, after)];

  const operations: Array<{kind: "equal" | "insert" | "delete"; line: string}> = [];
  let x = before.length;
  let y = after.length;
  for (let d = distance; d > 0; d -= 1) {
    const previousFrontier = trace[d];
    const diagonal = x - y;
    const previousDiagonal = diagonal === -d ||
        (diagonal !== d &&
          (previousFrontier?.get(diagonal - 1) ?? -1) <
            (previousFrontier?.get(diagonal + 1) ?? -1))
      ? diagonal + 1
      : diagonal - 1;
    const previousX = previousFrontier?.get(previousDiagonal) ?? 0;
    const previousY = previousX - previousDiagonal;
    while (x > previousX && y > previousY) {
      operations.push({kind: "equal", line: before[x - 1] ?? ""});
      x -= 1;
      y -= 1;
    }
    if (x === previousX) {
      operations.push({kind: "insert", line: after[y - 1] ?? ""});
      y -= 1;
    } else {
      operations.push({kind: "delete", line: before[x - 1] ?? ""});
      x -= 1;
    }
  }
  while (x > 0 && y > 0) {
    operations.push({kind: "equal", line: before[x - 1] ?? ""});
    x -= 1;
    y -= 1;
  }
  while (x > 0) {
    operations.push({kind: "delete", line: before[--x] ?? ""});
  }
  while (y > 0) {
    operations.push({kind: "insert", line: after[--y] ?? ""});
  }
  operations.reverse();

  const changes: TextLineChange[] = [];
  let beforeLine = 1;
  let afterLine = 1;
  let current: {beforeStartLine: number; afterStartLine: number; before: string[]; after: string[]} | null = null;
  const flush = () => {
    if (current === null) return;
    changes.push(current);
    current = null;
  };
  for (const operation of operations) {
    if (operation.kind === "equal") {
      flush();
      beforeLine += 1;
      afterLine += 1;
    } else {
      current ??= {
        beforeStartLine: beforeLine,
        afterStartLine: afterLine,
        before: [],
        after: [],
      };
      if (operation.kind === "delete") {
        current.before.push(operation.line);
        beforeLine += 1;
      } else {
        current.after.push(operation.line);
        afterLine += 1;
      }
    }
  }
  flush();
  return changes;
}

function wholeFileChange(
  before: readonly string[],
  after: readonly string[],
): TextLineChange {
  return {
    after,
    afterStartLine: 1,
    before,
    beforeStartLine: 1,
  };
}
