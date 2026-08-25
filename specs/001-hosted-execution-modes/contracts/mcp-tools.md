# Contract: MCP tool surface

Every change here is **additive**. An existing caller that sends today's
arguments gets today's behaviour (SC-001).

## `run_scan`

### Arguments — added

| Field | Type | Description |
|-------|------|-------------|
| `ref` | `string?` | Branch, tag, or commit to scan when `target` is a repository. May also be given inline as `target#ref`. Ignored for a local path. |
| `subdir` | `string?` | Scan only this path within the cloned repository. |

### Arguments — changed semantics

| Field | Was | Now |
|-------|-----|-----|
| `target` | Absolute path to a directory | A local path (unchanged), an HTTPS or SSH git URL, or `owner/repo` |

**Disambiguation rule**: anything naming an existing local path is treated as a
local path. No current caller's target can change meaning.

### Response — added

```jsonc
{
  "workspace": {
    "origin": "local_path | git_https | git_ssh",
    "source": "/home/me/project",      // normalized; never contains credentials
    "resolved_ref": "a1b2c3d…",        // null for a local path
    "credential_source": "github_app"  // name only, null when anonymous/local
  },
  "runs": [
    {
      "execution": {
        "backend": "docker | kubernetes"
        // …existing fields unchanged
      }
    }
  ]
}
```

### Error contract

| Condition | Result |
|-----------|--------|
| Target unparseable | Tool error naming the accepted forms |
| Host resolves to a private/loopback address | Tool error; refused before any connection |
| Private repository, no matching credential | Tool error naming the credential sources that would work. Must not reveal whether the repository exists. |
| Clone exceeds size/depth/time budget | Per-scanner `tool_error` naming the exceeded budget |
| No reachable execution backend | **One** preflight error, not one per scanner |

## `audit_status`

### Response — added

```jsonc
{
  "executor": {
    "backend": "docker | kubernetes",
    "available": true,
    "detail": "…"                      // why not, when unavailable
  },
  "workspace": {
    "git_available": true,
    "credential_sources": ["github_app", "ssh_key"],  // names only
    "remote_scanning_enabled": true
  },
  "transport": {
    "kind": "stdio | http",
    "authentication": "none | oauth2"
  }
  // …existing fields unchanged
}
```

`audit_status` must answer even when nothing is reachable — that is its job
(constitution V).

## Tools unchanged

`list_scanners`, `explain_finding`, and `suggest_fixes` are untouched.

## Invariants across all modes

1. A finding is not distinguishable by the backend that produced it: same rule
   IDs, same severities, same repository-relative paths (SC-003).
2. No response field, anywhere, contains credential material (SC-004).
3. A finding location is always relative to the repository root — never a
   temporary clone path, never a container mount path (FR-007).
