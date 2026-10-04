# Recon Agent

The Recon Agent is responsible for executing a comprehensive, multi-phased reconnaissance pipeline against sanctioned target URLs to map their attack surface and generate a highly structured `SiteMap` object. This sitemap acts as a well-defined contract consumed by downstream agents like the Planner Agent.

## Pipeline Phases

The Recon Agent executes its mapping process through several deterministic and bounded phases:

### Phase 0: Scope & Reachability
Verifies the target's reachability. Every network request issued in all phases is strictly bound by a `ScopeGuard`, ensuring the agent never interacts with out-of-scope or unsanctioned hosts.

### Phase 1: Fast HTTPx Crawl
Performs a fast, breadth-first search (BFS) crawl to discover traditional links, HTML forms, and API paths referenced inside JavaScript bundles.
* **Katana Integration (Phase 1b)**: Optionally hooks into ProjectDiscovery's `katana` headless crawler to discover deeply embedded routes that standard scraping might miss.

### Phase 2: API Surface Guessing
Probes common API structures and prefixes (`/api/v1/`, `/swagger`, `/openapi.json`, `robots.txt`, `sitemap.xml`) using safe GET requests.
* **AI-Directed Planning (Phase 2b)**: Optionally uses a Gemini model to suggest high-value API endpoints based on the already-discovered attack surface context. AI proposals are heavily sanitized and re-validated against the `ScopeGuard`.

### Phase 3: Authentication Detection & Post-Auth Crawl
Attempts to auto-login if credentials (`--username` and `--password`) are provided. It observes headers and payloads to detect JWTs or session cookies. If login succeeds, it executes a secondary crawl over the authenticated attack surface and probes for protected endpoints.

### Phase 4: Playwright Network Capture (SPA/XHR)
Spawns a Playwright headless browser to interact with single-page applications (SPAs). This captures runtime XHR/fetch requests, dynamically generated DOM links, and localStorage tokens (like JWTs) that are impossible to identify statically.

### Phase 5: Technology Fingerprinting
Aggregates fingerprints gathered during crawling (from HTTP headers, HTML bodies, cookies, and JWT claims) to identify the target's technology stack.

### Phase 6: Reflection Probing
Tests discovered parameters (such as URL queries and forms) by injecting benign markers to determine if the parameters are reflected in the HTTP response. Reflected parameters are flagged as high-priority candidates for XSS or SQLi testing.

## Output

The agent outputs an `agents.recon.core.models.SiteMap` object containing:
- Discovered endpoints, methods, and status codes.
- Detected technologies and frameworks.
- Authentication strategies and token artifacts.
- Execution statistics and operational notes.

## LangGraph Node

The Recon Agent is exposed as a LangGraph-compatible node (`recon_node`), making it fully interoperable with state-driven orchestration graphs. It expects a `ReconState` dictionary and returns the updated state containing the serialized `SiteMap`.
