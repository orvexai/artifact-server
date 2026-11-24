import {readFile, readdir} from "node:fs/promises";
import path from "node:path";

import {z} from "zod";
import {expect, test} from "vitest";

interface BrandOccurrence {
  readonly file: string;
  readonly line: number;
  readonly text: string;
}

const repositoryRoot = process.cwd();
const forbiddenBrand = /Artifact Server|Orvex(?:\s+Support)?/gu;
const sourceRoots = [
  "apps/web/src",
  "src/http",
  "src/shared",
  "src/cli",
  "src/mcp",
];
const integrationEntries = [
  "integrations/claude-channel/index.ts",
  "integrations/opencode/index.ts",
  "integrations/pi/index.ts",
];
const allowlistSchema = z.object({
  exceptions: z.array(z.object({file: z.string(), contains: z.string(), reason: z.string()})),
});

test("BRD-006-B: scanned product strings are Houston branded or explicitly allowlisted", async () => {
  const allowlist = allowlistSchema.parse(JSON.parse(
    await readFile(path.join(repositoryRoot, "project/spec/brand-naming-allowlist.json"), "utf8"),
  ));
  expect(allowlist.exceptions.every((item) =>
    !/(^|\/)(docs?|README|SKILL|apps\/site)(\/|$)/iu.test(item.file)
  )).toBe(true);

  const files = (await Promise.all(sourceRoots.map((root) => sourceFiles(root)))).flat();
  files.push(...integrationEntries);
  const occurrences = (await Promise.all(files.map((file) => occurrencesInFile(file)))).flat();
  const unexpected = occurrences.filter((item) =>
    !allowlist.exceptions.some((entry) =>
      entry.file === item.file && entry.contains.includes(item.text)
    )
  );

  expect(unexpected.map(formatOccurrence)).toEqual([]);
});

test("BRD-006-F: JSX text and continued template literals report their source line", () => {
  const jsx = findBrandLiterals(
    "return <p>Artifact Server</p>;\n",
    "apps/web/src/review/new-copy.tsx",
  );
  expect(jsx).toEqual([{file: "apps/web/src/review/new-copy.tsx", line: 1, text: "Artifact Server"}]);
  expect(jsx[0] && formatOccurrence(jsx[0])).toBe("apps/web/src/review/new-copy.tsx:1: Artifact Server");

  const template = findBrandLiterals(
    "const message = `Sign in to Houston Artifacts\nArtifact Server authorization\n`;",
    "src/cli/new-copy.ts",
  );
  expect(template).toEqual([{file: "src/cli/new-copy.ts", line: 2, text: "Artifact Server"}]);
  expect(template[0] && formatOccurrence(template[0])).toBe("src/cli/new-copy.ts:2: Artifact Server");
});

async function sourceFiles(root: string): Promise<string[]> {
  const entries = await readdir(path.join(repositoryRoot, root), {withFileTypes: true});
  const nested = await Promise.all(entries.map(async (entry) => {
    const file = path.posix.join(root, entry.name);
    if (entry.isDirectory()) return sourceFiles(file);
    return /\.(?:ts|tsx|js|jsx)$/u.test(entry.name) ? [file] : [];
  }));
  return nested.flat();
}

async function occurrencesInFile(file: string): Promise<BrandOccurrence[]> {
  return findBrandLiterals(await readFile(path.join(repositoryRoot, file), "utf8"), file);
}

function findBrandLiterals(source: string, file: string): BrandOccurrence[] {
  const result: BrandOccurrence[] = [];
  for (const [index, line] of stripComments(source).split("\n").entries()) {
    for (const match of line.matchAll(forbiddenBrand)) {
      result.push({file, line: index + 1, text: match[0]});
    }
  }
  return result;
}

function stripComments(source: string): string {
  source = source.replace(/\{\/\*[\s\S]*?\*\/\}/gu, (comment) =>
    comment.replace(/[^\n]/gu, " ")
  );
  let result = "";
  let mode: "code" | "single" | "double" | "template" | "regex" | "line-comment" | "block-comment" = "code";
  const templateReturnModes: Array<"code"> = [];
  const templateExpressionDepths: number[] = [];
  let regexCharacterClass = false;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index] ?? "";
    const next = source[index + 1] ?? "";
    if (mode === "line-comment") {
      if (character === "\n") {
        result += character;
        mode = "code";
      } else {
        result += " ";
      }
      continue;
    }
    if (mode === "block-comment") {
      if (character === "*" && next === "/") {
        result += "  ";
        index += 1;
        mode = "code";
      } else {
        result += character === "\n" ? "\n" : " ";
      }
      continue;
    }
    if (mode === "template") {
      if (character === "\\") {
        result += character + next;
        index += 1;
      } else if (character === "`") {
        result += character;
        mode = templateReturnModes.pop() ?? "code";
      } else if (character === "$" && next === "{") {
        result += "${";
        index += 1;
        templateExpressionDepths.push(1);
        mode = "code";
      } else {
        result += character;
      }
      continue;
    }
    if (mode === "regex") {
      result += character;
      if (character === "\\") {
        result += next;
        index += 1;
      } else if (character === "[") {
        regexCharacterClass = true;
      } else if (character === "]") {
        regexCharacterClass = false;
      } else if (character === "/" && !regexCharacterClass) {
        mode = "code";
      }
      continue;
    }
    if (mode === "single" || mode === "double") {
      result += character;
      if (character === "\\") {
        result += next;
        index += 1;
      } else if (mode === "single" && character === "'") {
        mode = "code";
      } else if (mode === "double" && character === "\"") {
        mode = "code";
      }
      continue;
    }
    const expressionDepth = templateExpressionDepths.length - 1;
    if (expressionDepth >= 0 && character === "{") {
      templateExpressionDepths[expressionDepth] = (templateExpressionDepths[expressionDepth] ?? 0) + 1;
    } else if (expressionDepth >= 0 && character === "}") {
      const depth = (templateExpressionDepths[expressionDepth] ?? 1) - 1;
      if (depth === 0) {
        templateExpressionDepths.pop();
        result += character;
        mode = "template";
        continue;
      }
      templateExpressionDepths[expressionDepth] = depth;
    }
    if (character === "/" && next === "/") {
      result += "  ";
      index += 1;
      mode = "line-comment";
    } else if (character === "/" && next === "*") {
      result += "  ";
      index += 1;
      mode = "block-comment";
    } else if (character === "/" && startsRegularExpression(result)) {
      result += character;
      regexCharacterClass = false;
      mode = "regex";
    } else if (character === "'") {
      result += character;
      mode = "single";
    } else if (character === "\"") {
      result += character;
      mode = "double";
    } else if (character === "`") {
      result += character;
      templateReturnModes.push("code");
      mode = "template";
    } else {
      result += character;
    }
  }
  return result;
}

function startsRegularExpression(source: string): boolean {
  const previous = source.trimEnd().at(-1) ?? "";
  return previous === "" || "([{:;,=!?&|+-*%^~<".includes(previous);
}
function formatOccurrence(item: BrandOccurrence): string {
  return `${item.file}:${item.line}: ${item.text}`;
}
