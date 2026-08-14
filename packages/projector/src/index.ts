export { createProjector, foldEntries } from "./fold.js";
export type { FoldOptions, ProjectorOptions } from "./fold.js";
export {
  CHANGE_KIND_SEVERITY,
  classifyChange,
  diffRegisters,
  resolveBaseline,
  scanInstants,
} from "./diff.js";
export { writeProjectionSqlite, readProjectionSqlite } from "./sqlite.js";
export {
  PocketBaseAdmin,
  PROJECTION_COLLECTIONS,
  PROPOSALS_COLLECTION,
  DAEMON_EVENTS_COLLECTION,
  DAEMON_STATUS_COLLECTION,
  ensureProjectionCollections,
  writeProjectionPocketBase,
  readProjectionPocketBase,
} from "./pocketbase.js";
export type { CollectionSpec, ProjectionSettings } from "./pocketbase.js";
