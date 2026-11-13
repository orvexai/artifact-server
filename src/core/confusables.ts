import data from "./unicode/confusables-data.json" with {type: "json"};
import {z} from "zod";

const confusablesDataSchema = z.object({
  map: z.record(z.string(), z.tuple([z.string(), z.string()])),
  unicodeVersion: z.string(),
});
const confusablesData = confusablesDataSchema.parse(data);
const confusables = confusablesData.map;

/** Version of the vendored Unicode UTS #39 confusables table. */
export const unicodeConfusablesVersion = confusablesData.unicodeVersion;

/** UTS #39 skeleton over the pinned table; pure and filesystem-free. */
export function confusableSkeleton(value: string): string {
  let output = "";
  for (const character of value.normalize("NFD")) {
    output += confusables[String(character.codePointAt(0))]?.[0] ?? character;
  }
  return output.normalize("NFD");
}
