import {describe, expect, test} from "vitest";

import {
  expectedPostgresMigrationHistory,
  requiredPostgresSchemaVersion,
} from "../../src/storage/postgres-migrations.js";

describe("postgres migration history", () => {
  test("covers every migration from 1 to the required version without gaps", () => {
    expect(expectedPostgresMigrationHistory.map((entry) => entry.migration_id))
      .toEqual(Array.from(
        {length: requiredPostgresSchemaVersion},
        (_, index) => index + 1,
      ));
  });

  test("names each migration and ends at the newest one", () => {
    expect(expectedPostgresMigrationHistory.every((entry) => entry.name.length > 0))
      .toBe(true);
    expect(expectedPostgresMigrationHistory.at(-1)).toEqual({
      migration_id: 20,
      name: "harden_guest_review",
    });
  });
});
