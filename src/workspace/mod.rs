//! Workspace provisioning: what a scan actually runs against.
//!
//! Either a caller-supplied local path, used as-is and never modified, or a
//! repository cloned to a temporary directory that this process owns and must
//! delete — on success, on failure, and on timeout.
