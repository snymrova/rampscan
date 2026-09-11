export { createProjector, foldEntries, monthsBefore, windowThreshold } from "./fold.js";
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
  KSI_CATALOG_COLLECTION,
  ensureProjectionCollections,
  writeProjectionPocketBase,
  writeKsiCatalogPocketBase,
  readProjectionPocketBase,
} from "./pocketbase.js";
export type { CollectionSpec, KsiCatalogRow, ProjectionSettings } from "./pocketbase.js";
