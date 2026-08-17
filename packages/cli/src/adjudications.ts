import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { PipelineAdjudication } from "@rampscan/schema";

// Adjudication loading (plan N1a-T1), beside `loadRecipes` and shaped like it:
// one file per control, parsed through the zod schema, refused on a duplicate.
//
// The directory may not exist — a checkout that carries no adjudications is a
// valid checkout, and `rampscan frontier` should report the whole frontier as
// unreviewed rather than crash. What is NOT tolerated is a file that fails the schema: a
// disposition without its reasoning, or a `partial` without its remainder, is
// exactly the failure ground rule 8 exists to catch, and it fails loudly here
// rather than rendering as a coverage number nobody can defend.

export async function loadAdjudications(dir: string): Promise<PipelineAdjudication[]> {
  let files: string[];
  try {
    files = (await readdir(dir)).filter((f) => f.endsWith(".json")).sort();
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw cause;
  }
  const records: PipelineAdjudication[] = [];
  for (const file of files) {
    const raw = JSON.parse(await readFile(join(dir, file), "utf8")) as unknown;
    try {
      records.push(PipelineAdjudication.parse(raw));
    } catch (cause) {
      throw new Error(
        `adjudication file ${file} does not match the PipelineAdjudication schema`,
        { cause },
      );
    }
  }
  const seen = new Set<string>();
  for (const record of records) {
    if (seen.has(record.controlId)) {
      throw new Error(`duplicate adjudication for control "${record.controlId}"`);
    }
    seen.add(record.controlId);
  }
  return records;
}
