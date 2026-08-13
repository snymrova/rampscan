export { createProjector, foldEntries } from "./fold.js";
export type { FoldOptions, ProjectorOptions } from "./fold.js";
export { writeProjectionSqlite, readProjectionSqlite } from "./sqlite.js";
export {
  PocketBaseAdmin,
  PROJECTION_COLLECTIONS,
  PROPOSALS_COLLECTION,
  DAEMON_EVENTS_COLLECTION,
  ensureProjectionCollections,
  writeProjectionPocketBase,
  readProjectionPocketBase,
} from "./pocketbase.js";
export type { CollectionSpec, ProjectionSettings } from "./pocketbase.js";
