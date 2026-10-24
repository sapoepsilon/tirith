import path from "node:path";

/**
 * Read-only view of the backend's evidence volume. The dashboard mounts TIRITH_DATA_DIR (the same
 * volume the backend writes) at TIRITH_EVIDENCE_DIR; only the `shots` subdirectory is served.
 */
export const EVIDENCE_DIR = path.resolve(process.env.TIRITH_EVIDENCE_DIR || ".data/evidence");