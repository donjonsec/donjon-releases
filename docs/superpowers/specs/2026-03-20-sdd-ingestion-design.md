# SDD Ingestion System Design

**Date:** 2026-03-20
**Status:** Draft
**Authors:** Cris + Claude
**Related:** `C:/Darkfactory/docs/plans/2026-03-14-precision-factory-design.md`

## Problem

The Precision Factory pipeline (Spec Engine -> Dev CT -> Validation -> Security -> Release -> Staging) requires structured specs as input. Today those specs are hand-written markdown. Two gaps exist:

1. **New projects** have no structured path from "I have an idea" to a factory-ready spec. The human writes freeform text, the Spec Engine does its best, and quality varies.
2. **Legacy projects** (donjon-platform: 48 TUI items, 17 scanners, 30 compliance frameworks, 11 export formats, web dashboard) were built through multiple spec cycles but never functionally tested as a whole. There is no systematic way to reverse-engineer what exists into specs that close the gap between "what it claims" and "what it does."

This design covers both ingestion paths and how they feed the factory pipeline.

---

## Part 1: New Project Interview

### Design Principles

- **Default mode: "ask me X questions."** The human dumps a stream-of-consciousness idea. The AI determines what to ask based on gaps — not a fixed sequence. The human can say "ask me 5 questions" or just start talking.
- Each answer narrows the next question (branching, not linear).
- Gharajedaghi's five properties are a **checklist the AI must cover**, not a fixed sequence: openness, purposefulness, multidimensionality, emergent properties, counterintuitiveness (inverse thinking). The AI tracks which properties have been addressed and weaves them into questions naturally.
- **Termination condition:** If 3 consecutive questions get short/trivial answers, or the AI cannot find meaningful gaps in the spec, propose synthesis. Don't keep asking when the questions feel forced.
- The interview produces two artifacts: **SPEC.md** (what to build) and **PROD.md** (all tasks to execute). SPEC.md maps to our factory spec format. PROD.md maps to the plan — iterate on tasks until each is detailed enough for the factory to execute.
- The human can bail at any point; partial specs are saved as drafts in Postgres `spec_archive` with `status: 'draft'`.

### Interaction Flow (Default)

```
Human: [dumps stream-of-consciousness idea]
   │
   ▼
AI: analyzes idea, identifies gaps against Gharajedaghi checklist
   │
   ▼
AI: "Here are N questions based on what I see missing..."
   │
   ▼
Human: answers (some briefly, some at length)
   │
   ▼
AI: updates internal gap tracker, asks follow-up questions
   │                                    │
   ▼                                    ▼
[Repeat until:]                    [Termination triggers:]
- All checklist items covered      - 3 consecutive short answers
- No meaningful gaps remain        - AI can't find real gaps
- Human says "that's enough"       - Readiness score > threshold
   │
   ▼
AI: "I think I have enough. Here's what I'd synthesize..." (proposes outline)
   │
   ▼
Human: approves or redirects
   │
   ▼
AI: writes SPEC.md → writes PROD.md → iterate on tasks until detailed → execute
```

### Gharajedaghi Checklist (AI Must Cover)

The AI tracks these internally and ensures each is addressed before proposing synthesis. They are woven into natural questions, not asked as a rigid sequence:

| Property | What the AI Must Uncover | Example Question |
|----------|-------------------------|------------------|
| **Openness** | External systems, boundaries, environment | "What does this interact with outside itself?" |
| **Purposefulness** | Conflicting purposes between parts | "Could optimizing X hurt Y?" |
| **Multidimensionality** | Multiple valid perspectives on the problem | "How would [persona B] see this differently?" |
| **Emergent Properties** | Behaviors only visible when parts combine | "What can't be tested by testing parts alone?" |
| **Counterintuitiveness** | Inverse thinking — what makes it fail by design | "What scenario makes a user say 'this is useless'?" |

### Question Flow (Hybrid: AI-Driven + Checklist)

The interview is **not** a fixed sequence. The AI determines question order based on what the human has said so far and what gaps remain. However, the AI must cover all question topics before synthesis.

The old Q1-Q12 fixed sequence is retained below as a **reference bank** — these are the topics the AI draws from, not a linear path. The AI may combine multiple topics in a single question, skip topics already covered by the human's initial dump, or dive deeper on topics where answers are thin.

```
Human dumps idea
       │
       ▼
AI: gap analysis against checklist
       │
       ├──→ [Purpose + Personas]      (if not clear from dump)
       ├──→ [Core Requirements]        (if not enumerated)
       ├──→ [Inverse Thinking]         (per requirement — always ask)
       ├──→ [I/O Definition]           (if interfaces unclear)
       ├──→ [Acceptance Criteria]      (if success conditions vague)
       ├──→ [External Systems]         (openness — if boundaries unclear)
       ├──→ [Purposefulness]           (if multiple parts exist)
       ├──→ [Emergent Properties]      (if integration matters)
       ├──→ [Deployment & Scale]       (if not mentioned)
       ├──→ [Existing Codebase]        (if not greenfield)
       └──→ [NFR]                      (domain-specific constraints)
       │
       ▼
[3 short answers in a row OR no gaps?] ──→ PROPOSE SYNTHESIS
       │
       ▼
SPEC.md + PROD.md
```

### Question Reference Bank

> These are **not** asked in order. The AI draws from this bank based on gaps in what the human has provided. Each question includes its output field mapping so the AI knows what data it needs to fill the spec.

#### Q1: Purpose
> "What does this feature/product do? Describe it in one paragraph as if explaining to a new team member."

**Output field:** `spec.purpose`
**Branching:** If the answer mentions multiple distinct capabilities, the interviewer splits them and asks: "I see N distinct capabilities. Should these be separate modules or one?" This determines the module count for the rest of the interview.

#### Q2: Personas
> "Who uses this? Name the 1-3 types of people who will interact with it, and what each one needs from it."

**Output field:** `spec.personas[]`
**Branching:** If persona count > 3, push back: "Pick the 3 most important. The others become future scope." If the answer is vague ("developers"), probe: "What kind of developer? What are they doing when they reach for this tool?"

#### Q3: Core Requirements
> "What are the 3 most important things it must do? Not 5. Not 10. Three. If it does these three things well, would you ship it?"

**Output field:** `spec.requirements[]` (seeded with 3 items)
**Branching:** If the human lists more than 3, force-rank: "Order these by user impact. The top 3 become v1. The rest go to the backlog." If fewer than 3, probe: "Is this really a standalone feature, or part of something larger?"

#### Q4: Inverse Thinking (per requirement)
> "For requirement [X]: What would make this fail for a real user? Not a bug — a design failure. What scenario would make someone say 'this is useless'?"

**Output field:** `spec.requirements[n].failure_modes[]`
**Rationale:** Gharajedaghi's counterintuitiveness principle. The failure modes become edge cases and negative test cases. This is where most specs fall apart — they describe the happy path but not the ways reality breaks it.
**Branching:** For each failure mode, ask: "Is this a hard constraint (must never happen) or a degraded-but-acceptable scenario?" This determines whether the acceptance criteria use MUST or SHOULD.

#### Q5: I/O Definition (per requirement)
> "For requirement [X]: What goes in? What comes out? Be specific — data types, formats, ranges."

**Output fields:**
- `spec.requirements[n].input` — typed interface
- `spec.requirements[n].output` — typed interface
- `spec.requirements[n].edge_cases[]` — derived from Q4 failure modes + probing

**Branching:** If the input/output involves another system's data, cross-reference Q7 (external systems). If the human says "JSON" without specifying shape, probe for the schema.

#### Q6: Acceptance Criteria (per requirement)
> "For requirement [X]: Write the acceptance test. Given [setup], When [action], Then [expected result]."

**Output field:** `spec.requirements[n].acceptance_criteria[]`
**Format:** Given/When/Then triples that map directly to factory eval configs.
**Branching:** For each failure mode from Q4, generate a negative acceptance criterion: "Given [setup], When [failure trigger], Then [expected graceful behavior]." Present these to the human for confirmation.

#### Q7: External Systems (Openness)
> "What existing systems does this interact with? APIs, databases, file systems, other modules, third-party services."

**Output field:** `spec.dependencies[]`
**Branching:** For each dependency, ask: "Is this dependency required (hard) or optional (graceful degradation)?" and "Does this system already exist, or does the factory need to build it?" Hard dependencies become contract references. Optional dependencies get fallback behavior specs.

#### Q8: Purposefulness
> "Look at the parts we've defined. Can any of their purposes conflict? For example: a caching layer wants speed, but an audit layer wants completeness. Where might optimization of one part hurt another?"

**Output field:** `spec.tensions[]`
**Rationale:** Gharajedaghi's purposefulness. Parts of a system have their own purposes that can conflict with the whole. Surfacing these tensions early prevents the factory from producing code that optimizes locally but fails globally.
**Branching:** If tensions exist, ask: "Which purpose wins when they conflict? What's the resolution policy?" This becomes a non-functional constraint.

#### Q9: Emergent Properties
> "What behavior only appears when all the parts work together? What can't be tested by testing each module in isolation?"

**Output field:** `spec.integration_tests[]`
**Rationale:** Gharajedaghi's emergent properties. The factory's plane pipeline tests modules individually (Validation Plane) and as a system (Staging Plane). This question defines what the Staging Plane must verify that the Validation Plane cannot.
**Branching:** If the human struggles, offer examples from the domain: "For a security scanner: does the scan orchestration correctly chain scanner results into a unified report? That's emergent — no individual scanner test catches it."

#### Q10: Deployment & Scale
> "Where does this run? Cloud, on-prem, both? How many users — 10, 1000, 100K? What data does it handle — PII, PHI, financial, classified?"

**Output fields:**
- `spec.deployment` — cloud/on-prem/hybrid/edge/air-gap
- `spec.scale` — user count, data volume, throughput expectations
- `spec.data_sensitivity` — PII/PHI/financial/classified/public
**Branching:** Data sensitivity auto-injects requirements: PII → encryption at rest + GDPR consideration. PHI → HIPAA controls. Classified → air-gap mandatory. Scale above 1000 → PostgreSQL not SQLite, connection pooling, caching layer.

#### Q11: Existing Codebase (if not greenfield)
> "Is this adding to an existing project? If yes, what's the tech stack, what patterns does it follow, and where should this new feature live?"

**Output fields:**
- `spec.existing_codebase` — repo path, language, framework
- `spec.conventions` — file organization, naming, testing patterns
- `spec.integration_points` — where the new feature connects to existing code
**Branching:** If existing codebase, the plan phase must reference actual files and patterns. If greenfield, skip.

#### Q12: Non-Functional Requirements
> "Any other constraints? Performance budgets, security certifications, accessibility, browser support, backward compatibility?"

**Output field:** `spec.nfr`
**Branching:** If the product is security-related, auto-inject: "Zero retention mode? Air-gap? FIPS?" If web-facing: "WCAG compliance? IE11 support?" Based on domain knowledge from Q1.

### Synthesis

When the termination condition triggers (3 consecutive short answers, no meaningful gaps, or human says "enough"), the AI proposes synthesis. The synthesis produces two documents:

**SPEC.md** (what to build):
1. Generates the module breakdown from requirements + dependencies
2. Creates interface contracts per module (typed I/O)
3. Builds the dependency graph
4. Converts Given/When/Then into promptfoo eval YAML configs
5. Adds negative test cases from inverse thinking / failure modes
6. Adds integration test specs from emergent properties analysis
7. Adds non-functional constraints

**PROD.md** (how to build it):
1. Breaks the spec into ordered tasks
2. Each task has: description, acceptance criteria, estimated complexity, dependencies on other tasks
3. Tasks are iterated with the human until each is detailed enough for the factory to execute without ambiguity
4. Task granularity target: each task should be one factory pipeline run (one module, one contract, one eval)

The synthesized SPEC.md is presented for human approval (factory Touchpoint 1). Nothing executes until approved. PROD.md is the execution plan the factory follows.

### Interview State Machine

```
States: NOT_STARTED, IN_PROGRESS, SYNTHESIZING, REVIEW, TASK_REFINEMENT, APPROVED, REJECTED

Transitions:
  NOT_STARTED → IN_PROGRESS     (human dumps idea or starts interview)
  IN_PROGRESS → IN_PROGRESS     (each Q&A round — AI asks N questions, human answers)
  IN_PROGRESS → SYNTHESIZING    (termination triggers: 3 short answers, no gaps, or human says "done")
  SYNTHESIZING → REVIEW         (SPEC.md + PROD.md generated, presented to human)
  REVIEW → TASK_REFINEMENT      (human approves spec, iterates on task detail in PROD.md)
  TASK_REFINEMENT → TASK_REFINEMENT (iterate tasks until granular enough)
  TASK_REFINEMENT → APPROVED    (human approves tasks — enters factory pipeline)
  REVIEW → IN_PROGRESS          (human requests changes — AI re-opens questioning on specific gaps)
  REVIEW → REJECTED             (human abandons — save as draft)
```

**Internal tracking (persisted in Postgres JSONB):**
- `checklist_coverage`: which Gharajedaghi properties have been addressed
- `consecutive_short_answers`: counter toward termination trigger (resets on substantive answer)
- `readiness_score`: 0-100, computed from checklist coverage + spec field completeness
- `answers`: all Q&A pairs with timestamps

Partial state persists in Postgres `spec_archive` with `status: 'draft'` and answers-so-far in the `spec` JSONB column. The human can resume later.

---

## Part 2: Legacy Project Ingestion

### The Problem with Legacy

The donjon-platform was built through multiple factory spec cycles. Each cycle produced working code for that spec's scope. But:

- No cycle tested the whole product end-to-end
- Menu items were added but some call modules that were never completed
- Some modules import correctly but fail at runtime (missing config, missing tools, wrong paths)
- The gap between "what the menu advertises" and "what actually works" is unknown

### Ingestion Algorithm

```
SCAN ──→ CLAIM ──→ TEST ──→ GAP ──→ SPEC
  │         │        │        │        │
  │         │        │        │        └─ Factory-ready SDD specs
  │         │        │        └─ Delta between claim and reality
  │         │        └─ Functional execution results
  │         └─ What it says it does (docs, docstrings, marketing)
  └─ Static analysis of codebase structure
```

#### Phase 1: SCAN (Static Analysis)

Walk the codebase and build a structural inventory. No execution. Language-agnostic.

**Inputs:** Repository root path + language hint (auto-detected if not provided)
**Outputs:** `inventory.json` — complete structural map

**Language detection:** Check for `pyproject.toml`/`setup.py` (Python), `package.json` (JS/TS), `go.mod` (Go), `Cargo.toml` (Rust), `pom.xml`/`build.gradle` (Java), `*.csproj` (C#). Multiple languages = multi-language project, scan each.

What to extract (generic — adapt per language):

| Element | How to Find (any language) |
|---------|---------------------------|
| **Entry points** | CLI scripts, main functions, binary targets, `[project.scripts]`, `bin/`, `cmd/`, `package.json scripts` |
| **API endpoints** | Route decorators, handler registrations, OpenAPI specs, controller annotations |
| **Modules/packages** | Directory structure + language module conventions (`lib/`, `src/`, `pkg/`, `internal/`) |
| **Classes/functions** | AST parse per language (Python ast, TypeScript ts-morph, Go go/parser) |
| **UI components** | Menu definitions, page routes, component files (`.astro`, `.tsx`, `.vue`, `.svelte`) |
| **Configuration** | Config files (YAML, TOML, JSON, .env), schema definitions |
| **Dependencies** | Package manifests (`requirements.txt`, `package.json`, `go.mod`, `Cargo.toml`) |
| **External tool deps** | Subprocess calls, exec calls, `shutil.which`, system command invocations |
| **Test files** | `test_*`, `*_test.go`, `*.spec.ts`, `*.test.js` — count and categorize |
| **Documentation** | README, docs/, docstrings, JSDoc, Go doc comments |

The inventory is a JSON document:

```json
{
  "product": "donjon-platform",
  "version": "7.3.0",
  "scan_date": "2026-03-20T...",
  "menu_items": [
    {
      "id": 1,
      "label": "Quick Assessment (15-30 min)",
      "handler": "run_assessment('quick')",
      "source_file": "bin/donjon:159",
      "calls": ["lib/orchestrator.py:AssessmentOrchestrator.run_full_assessment"]
    }
  ],
  "modules": [...],
  "scanners": [...],
  "api_endpoints": [...],
  "frameworks": [...],
  "export_formats": [...],
  "external_tools": [...]
}
```

#### Phase 2: CLAIM (Documentation Extraction)

For each item in the inventory, extract what it *claims* to do.

**Sources (priority order):**
1. Docstrings on the class/function
2. README sections
3. Marketing copy (website, FEATURES-v7.md)
4. Inline comments
5. Variable/function names (last resort — weakest signal)

**Output:** Each inventory item gets a `claim` field:

```json
{
  "id": 1,
  "label": "Quick Assessment",
  "claim": "Runs network discovery, vulnerability scan, SSL check, and compliance check in parallel. Produces a unified report with findings prioritized by CVSS score. Completes in 15-30 minutes.",
  "claim_sources": ["bin/donjon:127", "docs/FEATURES-v7.md:42", "lib/orchestrator.py:docstring"]
}
```

#### Phase 3: TEST (Functional Execution)

Run each item and record what actually happens. This is where reality meets claims.

**Execution environment:** CT 100 (factory-core) or a dedicated test CT. The product must be installed and runnable.

**Test categories:**

| Category | Test Method | Pass Criteria |
|----------|-------------|---------------|
| **Import test** | `python -c "from lib.X import Y"` | No ImportError |
| **Instantiation test** | Create the class, call `__init__` | No exception, object exists |
| **Smoke test** | Call the primary method with minimal valid input | Returns something (not crash) |
| **Functional test** | Call with realistic input, validate output shape | Output matches documented contract |
| **Integration test** | Call through the TUI/API path the user would use | End-to-end path works |

**Test execution order:** Import → Instantiation → Smoke → Functional → Integration. Stop at the first failure level for each item. No point running functional tests on something that can't import.

**Output:** Each inventory item gets a `test_result` field:

```json
{
  "id": 1,
  "label": "Quick Assessment",
  "test_result": {
    "status": "broken",
    "level_reached": "smoke",
    "import": {"pass": true, "details": null},
    "instantiation": {"pass": true, "details": null},
    "smoke": {"pass": false, "error": "AssessmentOrchestrator.__init__ requires 'config' param not documented", "traceback": "..."},
    "functional": null,
    "integration": null
  }
}
```

**Status classification:**

| Status | Definition |
|--------|------------|
| **works** | Passes all test levels through integration |
| **partial** | Passes smoke but fails functional or integration (does something, but not what it claims) |
| **broken** | Fails at import, instantiation, or smoke level |
| **stub** | Imports and instantiates, but primary method raises `NotImplementedError` or returns hardcoded placeholder |

#### Phase 4: GAP (Delta Analysis)

Compare claim to reality for each item. The gap IS the spec.

```
Gap = Claim - Reality

If gap is empty → item works as advertised → regression test spec
If gap is non-empty → item is broken/partial → fix spec
If claim is empty but code exists → undocumented feature → documentation spec
If claim exists but code doesn't → vaporware → build spec or remove from marketing
```

**Gap document per item:**

```json
{
  "id": 1,
  "label": "Quick Assessment",
  "status": "broken",
  "claim": "Runs network discovery, vuln scan, SSL check, compliance check in parallel...",
  "reality": "Fails at smoke: AssessmentOrchestrator requires config param not in documented interface",
  "gaps": [
    {
      "type": "interface_mismatch",
      "description": "Constructor requires 'config' parameter but bin/donjon calls it with no arguments",
      "severity": "blocking",
      "fix_category": "code_fix"
    }
  ],
  "spec_action": "fix"
}
```

#### Phase 5: SPEC (Factory-Ready Output)

Convert each gap into a factory-ready SDD spec. The spec format matches the factory's Spec Engine parser (interface contracts with typed I/O, dependency declarations, eval configs).

**For broken/stub items — Fix Spec:**

```markdown
## Module: orchestrator

### Purpose
Assessment orchestration — runs multiple scanners in parallel, aggregates results.

### Interface Contract
- **Input:** `AssessmentOrchestrator(config: Optional[dict] = None)`
- **Output:** `run_full_assessment(type: str) -> dict` returning `{session_id, summary: {total_findings, ...}, results: [...]}`
- **Errors:** `ScannerNotFound`, `ConfigurationError`, `TimeoutError`
- **Dependencies:** `network_scanner`, `vulnerability_scanner`, `ssl_scanner`, `compliance_scanner`, `config`

### Acceptance Criteria

Given a running Donjon Platform installation with nmap available
When `AssessmentOrchestrator().run_full_assessment('quick')` is called
Then it returns a dict with keys: session_id, summary, results
And summary.total_findings is an integer >= 0
And the call completes within 1800 seconds

Given a Donjon Platform installation without nmap
When `AssessmentOrchestrator().run_full_assessment('quick')` is called
Then it raises `ScannerNotFound` with a message naming the missing tool
And it does not crash or hang

### Edge Cases (from inverse thinking)
- All scanners fail → should still return a valid result dict with 0 findings and error details per scanner
- Target is unreachable → should timeout gracefully, not hang
- Config file missing → should use defaults, not crash

### promptfoo Eval Config
[Auto-generated YAML from acceptance criteria]
```

**For working items — Regression Spec:**

```markdown
## Module: ssl_scanner

### Status: WORKING (regression protection)

### Acceptance Criteria (current behavior — do not break)

Given a target host running HTTPS on port 443
When `SSLScanner().scan(target)` is called
Then it returns findings with fields: cipher_suites, protocol_versions, certificate_info
And each finding has severity in [critical, high, medium, low, info]

### Baseline
- Test date: 2026-03-20
- Test target: [specific target used]
- Output hash: [sha256 of normalized output]
```

---

## Part 3: Example Application — Donjon Platform

> This section applies the generic ingestion framework (Parts 1-2) to the donjon-platform as the first real-world test case. The same process applies to any project — PurpleTeamGRC, darkfactory, donjonsec-website, or any external codebase.

### Scope

The donjon-platform has the following surface area to ingest:

| Category | Count | Source |
|----------|-------|--------|
| TUI menu items | 15 (from `bin/donjon` `show_menu()`) | `bin/donjon:121-154` |
| Scanner modules | 17 (in `scanners/`) | `scanners/*.py` |
| Lib modules | 55+ (in `lib/`) | `lib/*.py` |
| Compliance frameworks | 30 (claimed) | Config files + `lib/compliance.py` |
| Export formats | 11 (claimed) | `lib/export.py`, `lib/pdf_export.py` |
| Web dashboard | 1 (Flask app) | `web/` |
| CLI tools | 12+ (in `bin/`) | `bin/*.py`, `bin/donjon-*` |
| API endpoints | Unknown until scan | `web/` route decorators |

### Execution Plan

**Step 1: Automated Scan (Phase 1)**
Run the scanner against `C:/Users/Cris/donjon-platform-clean/`. Produces `inventory.json`.

**Step 2: Claim Extraction (Phase 2)**
Cross-reference inventory with:
- `docs/FEATURES-v7.md`
- `README.md`
- `docs/CLI-REFERENCE.md`
- `docs/API-REFERENCE.md`
- Per-module docstrings

**Step 3: Functional Testing on CT 100 (Phase 3)**
Deploy to CT 100. Run test battery:

```
For each menu item (1-15):
  - Simulate the menu selection
  - Run the handler function
  - Capture stdout, stderr, return value, exceptions
  - Classify: works | partial | broken | stub

For each scanner (17):
  - Import test
  - Instantiation test
  - Smoke test against localhost or a test target (CT 102-104)
  - Functional test: does output match BaseScanner contract?

For each export format (11):
  - Generate with sample data
  - Validate output format (JSON schema, CSV structure, PDF readability)

For each compliance framework (30):
  - Load framework definition
  - Run compliance check against test target
  - Validate output has required fields

For the web dashboard:
  - Start server
  - Hit health endpoint
  - Hit each API route
  - Validate response shapes
```

**Step 4: Gap Analysis (Phase 4)**
Produce gap documents. Expected distribution (estimate based on v7.3.0 hardening history):

| Status | Expected % | Action |
|--------|-----------|--------|
| Works | 30-40% | Regression specs |
| Partial | 20-30% | Fix specs (output wrong, missing fields, incomplete) |
| Broken | 20-30% | Fix specs (crashes, missing deps, wrong interfaces) |
| Stub | 10-20% | Build specs (NotImplementedError, placeholder returns) |

**Step 5: Spec Generation (Phase 5)**
Produce factory-ready specs. Prioritized by user impact:

**Priority 1 (Critical Path):** Menu items 1-3 (assessments) — these are the primary user workflow
**Priority 2 (Core Scans):** Menu items 4-8 (individual scans) — the building blocks
**Priority 3 (Output):** Menu items 9-11 (reports, exports, results) — users need output
**Priority 4 (Operations):** Menu items 12-15 (scheduling, config, system check) — operational
**Priority 5 (Dashboard):** Web dashboard — secondary interface
**Priority 6 (Advanced):** MSSP features, multi-tenant, agent deployer — future

### Prioritization Algorithm

```
impact_score = (
    user_frequency    * 0.4 +  # How often is this used? (menu position as proxy)
    dependency_count  * 0.3 +  # How many other features depend on this?
    fix_complexity    * -0.2 + # Simpler fixes first (quick wins)
    revenue_impact    * 0.1    # Does this block a paid tier?
)
```

Items sorted by `impact_score` descending. Ties broken by dependency order (fix dependencies before dependents).

---

## Part 4: Factory Pipeline Integration

### How Specs Enter the Pipeline

```
                    ┌────────────────────┐
                    │  Interview (Way 1) │
                    │  or                │
                    │  Ingestion (Way 2) │
                    └────────┬───────────┘
                             │
                             ▼
                    ┌────────────────────┐
                    │   spec_archive     │
                    │   (Postgres)       │
                    │   status: draft    │
                    └────────┬───────────┘
                             │ Human approves (Touchpoint 1)
                             ▼
                    ┌────────────────────┐
                    │   Spec Engine      │
                    │   (Factory)        │
                    │   Expands into     │
                    │   contracts +      │
                    │   eval configs     │
                    └────────┬───────────┘
                             │
                             ▼
                    ┌────────────────────┐
                    │   Factory Pipeline │
                    │   Dev → Val →      │
                    │   Sec → Rel →      │
                    │   Staging          │
                    └────────┬───────────┘
                             │
                             ▼
                    ┌────────────────────┐
                    │   Re-Test          │
                    │   (Ingestion       │
                    │    Phase 3 again)  │
                    └────────┬───────────┘
                             │
                       ┌─────┴─────┐
                       ▼           ▼
                    PASS         FAIL
                    (close       (update spec,
                     spec)       re-enter pipeline)
```

### Spec Format for Factory Consumption

The Spec Engine (Section 1 of the Precision Factory design) expects specs to produce:

1. **Module breakdown** — list of modules with responsibilities
2. **Interface contracts** — typed I/O per module (the TypeScript-style contracts from the design doc)
3. **Dependency graph** — which modules depend on which
4. **promptfoo eval configs** — YAML per contract
5. **Non-functional requirements** — performance, security constraints

Both ingestion paths (interview and legacy) produce specs in this format. The interview synthesizes from Q&A answers. The legacy ingestion synthesizes from gap analysis.

### Spec Document Structure

```markdown
# SDD Spec: {module_name}

## Metadata
- Product: {product}
- Module: {module_name}
- Version: {version}
- Source: interview | legacy_ingestion
- Priority: {1-6}
- Status: draft | approved | executing | completed | failed

## Purpose
{One paragraph from Q1 or CLAIM phase}

## Personas
{From Q2 or inferred from product docs}

## Interface Contract
{TypeScript-style typed I/O}

## Dependencies
{List with hard/optional classification}

## Acceptance Criteria
{Given/When/Then blocks}

## Edge Cases
{From Q4 inverse thinking or Phase 4 gap analysis}

## Integration Tests
{From Q9 or inferred from dependency graph}

## Non-Functional Requirements
{From Q10 or product defaults}

## promptfoo Eval Config
{YAML block — auto-generated from acceptance criteria}

## Gap Analysis (legacy only)
- Claim: {what it says it does}
- Reality: {what it actually does}
- Gaps: {list of deltas}
- Fix category: code_fix | interface_fix | config_fix | build_from_scratch
```

### Feedback Loop

After the factory produces code from a spec:

1. **Re-test:** Run the legacy ingestion Phase 3 (TEST) against the factory output
2. **Compare:** Did the gaps close?
3. **If gaps remain:** Update the spec with new gap data, re-enter pipeline
4. **If all gaps closed:** Mark spec as `completed` in `spec_archive`, generate regression spec
5. **Regression specs** are stored alongside fix specs and run on every subsequent factory cycle to prevent regressions

The feedback loop is the circular causality from Gharajedaghi — the output of the system (factory-produced code) feeds back as input (re-test results) to modify the system's next action (updated spec).

---

## Part 5: Forgejo Integration

### Repository Structure

Specs live in the product repo, versioned alongside code:

```
donjon-platform-clean/
├── docs/
│   └── superpowers/
│       └── specs/
│           ├── inventory.json              # Phase 1 output
│           ├── claims.json                 # Phase 2 output
│           ├── test-results.json           # Phase 3 output
│           ├── gaps.json                   # Phase 4 output
│           ├── backlog.json                # Prioritized spec queue
│           ├── fix/                        # Fix specs (broken/stub items)
│           │   ├── orchestrator.md
│           │   ├── network-scanner.md
│           │   └── ...
│           ├── regression/                 # Regression specs (working items)
│           │   ├── ssl-scanner.md
│           │   └── ...
│           └── new/                        # New feature specs (from interview)
│               └── ...
```

### Forgejo Workflow

1. **Ingestion runs** produce a branch: `specs/ingestion-{date}`
2. **Specs are committed** to that branch with structured commit messages: `spec(fix): orchestrator — interface mismatch`
3. **PR created** from ingestion branch to main — human reviews the batch
4. **Approved specs** get tagged with a Forgejo label: `factory-ready`
5. **Factory picks up** specs with `factory-ready` label via the Forgejo API
6. **Factory results** are committed to a branch: `factory/{spec-name}-{run-id}`
7. **Re-test results** update the spec files in-place (gap fields updated, status changed)

### Automation Hooks

```
Forgejo webhook → Factory API:
  - On label "factory-ready" added → queue spec for pipeline
  - On PR merged to main → trigger regression test suite
  - On factory completion → create PR with results + updated specs
```

---

## Part 6: Web Portal (Primary Interface)

### Overview

A self-hosted web portal replaces CLI-based interaction as the primary interface for spec intake, factory monitoring, and review. Built with FastAPI + HTMX + Tailwind CSS — no React, no SPA complexity. Runs on a CT alongside Forgejo.

### Architecture

```
┌─────────────────────────────────────────────────────┐
│  Browser (HTMX + Tailwind)                          │
│  ┌─────────┐ ┌──────────┐ ┌────────┐ ┌───────────┐ │
│  │Dashboard│ │New Proj  │ │Ingest  │ │Review     │ │
│  │         │ │Interview │ │Existing│ │Queue      │ │
│  └────┬────┘ └────┬─────┘ └───┬────┘ └─────┬─────┘ │
└───────┼───────────┼────────────┼────────────┼───────┘
        │           │            │            │
        ▼           ▼            ▼            ▼
┌─────────────────────────────────────────────────────┐
│  FastAPI Backend                                     │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐           │
│  │Interview │ │Ingestion  │ │Factory   │           │
│  │Engine    │ │Pipeline   │ │Status    │           │
│  └────┬─────┘ └─────┬─────┘ └────┬─────┘           │
│       │              │            │                  │
│  ┌────▼──────────────▼────────────▼─────┐           │
│  │  SQLAlchemy → Factory Postgres       │           │
│  │  (spec_archive, dependency_edges,    │           │
│  │   system_registry, failure_ledger)   │           │
│  └──────────────────────────────────────┘           │
│       │                                              │
│  ┌────▼─────────────┐  ┌───────────────┐            │
│  │ Ollama API       │  │ SSE endpoint  │            │
│  │ (AI questioning) │  │ (live updates)│            │
│  └──────────────────┘  └───────────────┘            │
└─────────────────────────────────────────────────────┘
```

### Pages

#### Dashboard
- Active interviews (in-progress specs with readiness scores)
- Recently completed specs (last 7 days)
- Factory pipeline status (running, queued, failed)
- Quick stats: specs total, approved, in-factory, completed

#### "New Project" — Interactive Interview
The intake form implements the hybrid questioning pattern:

```
JSON Schema defines initial form fields
       │
       ▼
Server renders form via Jinja2 + HTMX
       │
       ▼
Human fills initial dump (freeform textarea + optional structured fields)
       │
       ▼
AI analyzes gaps against Gharajedaghi checklist
       │
       ▼
HTMX swaps in follow-up question section (hx-swap="innerHTML")
       │
       ▼
Human answers → AI analyzes → HTMX swaps next questions
       │
       ▼
[Loop until readiness score passes threshold]
       │
       ▼
AI proposes SPEC.md outline → human approves/edits inline
       │
       ▼
Spec enters triage (review queue) → human approves → factory processes
```

**Key UX decisions:**
- The initial form has a large freeform textarea ("dump your idea here") plus optional structured fields (project name, tech stack, personas)
- Follow-up questions appear below the initial dump — the human can scroll up to see context
- Each AI question round shows 3-5 questions, not one at a time (web != CLI — batch is better for forms)
- Readiness score displayed as a progress bar with breakdown by checklist item
- "That's enough" button always visible — human can force synthesis at any point

#### "Ingest Existing Project"
- Input: Forgejo repo URL or local path
- Triggers: SCAN -> CLAIM -> TEST -> GAP -> SPEC pipeline
- Live progress via SSE (each phase reports status)
- Results displayed as an inventory table with status badges (works/partial/broken/stub)
- Gap analysis shown inline with "Generate Fix Spec" buttons per item

#### "Factory Status"
- Live pipeline view: which specs are in Dev, Validation, Security, Release, Staging
- `failure_ledger` display: failed specs with error details and retry count
- `solutions_memory` display: patterns the factory has learned
- SSE-powered — updates without page refresh

#### "Review Queue"
- Specs waiting for human approval (factory Touchpoint 1)
- Each spec shown with: purpose summary, readiness score, checklist coverage, diff from previous version
- Approve / Reject / Request Changes actions
- Approved specs auto-enter factory pipeline
- Factory-produced diffs shown for review before merge

### Technical Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Backend | FastAPI | Already in our stack, async-native, great for SSE |
| Templates | Jinja2 | FastAPI native, server-rendered |
| Dynamic UI | HTMX | No JS framework needed, progressive enhancement, proven for internal tools |
| Styling | Tailwind CSS | Utility-first, no custom CSS maintenance |
| ORM | SQLAlchemy | Maps to existing factory Postgres schema |
| AI | Ollama API (local) | No external API dependency, uses existing CT 100 models |
| Live updates | SSE (Server-Sent Events) | Simpler than WebSockets for one-way updates |
| Auth | None (MVP) → API key → SSO (full) | Internal tool, single-user initially |

### Industry Reference

This architecture draws from research into how others solve similar problems:

| Product | Pattern Borrowed | How We Apply It |
|---------|-----------------|-----------------|
| **Backstage** (Spotify) | JSON Schema-driven forms for software templates | Our intake form: JSON Schema defines fields, server renders, AI extends dynamically |
| **Replit Agent** | "Ask until done" pattern — AI keeps questioning until it has enough context | Our hybrid interview mode — AI determines questions, terminates when gaps close |
| **Linear** | Triage inbox — items enter a queue, get triaged, then scheduled | Our review queue — specs enter triage, human approves, factory schedules |
| **Port** (getport.io) | Self-service actions + scorecards for service maturity | Our readiness scorecards + "Ingest Existing Project" self-service |
| **HTMX consensus** | Internal tools community consensus: HTMX > React for admin dashboards | No SPA, no build step, server-rendered with progressive enhancement |

---

## Part 7: Spec Engine Parser Compatibility

The existing Spec Engine (Section 1 of the Precision Factory design) parses structured markdown specs into interface contracts. The ingestion system must produce specs that the Spec Engine can consume without modification.

### Required Fields (Spec Engine Contract)

| Field | Type | Required | Source (Interview) | Source (Legacy) |
|-------|------|----------|-------------------|-----------------|
| `product` | string | yes | Q1 context | inventory scan |
| `module` | string | yes | Synthesized from Q3 | inventory scan |
| `purpose` | string | yes | Q1 | CLAIM phase |
| `interface.input` | typed object | yes | Q5 | AST parse + gap fix |
| `interface.output` | typed object | yes | Q5 | AST parse + gap fix |
| `interface.errors` | typed object | yes | Q4 + Q6 | gap analysis |
| `dependencies` | string[] | yes | Q7 | inventory scan |
| `acceptance_criteria` | Given/When/Then[] | yes | Q6 | gap-derived |
| `edge_cases` | string[] | yes | Q4 | gap analysis |
| `nfr` | object | no | Q10 | product defaults |
| `eval_config` | YAML | auto-generated | From Q6 | From acceptance_criteria |

### Spec-to-Contract Translation

The Spec Engine reads the markdown spec and produces:

1. A TypeScript-style interface contract (for the Dev CT)
2. A promptfoo eval YAML (for the Validation Plane)
3. A dependency graph entry (for Postgres `dependency_edges`)
4. A registry entry (for Postgres `system_registry`)

The ingestion system does NOT produce these artifacts directly — it produces the spec markdown, and the Spec Engine handles the translation. This keeps the boundary clean: ingestion produces specs, Spec Engine produces contracts.

### Spec Validation

Before a spec enters the factory pipeline, validate:

1. All required fields present
2. Interface types are parseable (not vague — "dict" is not a type, `dict[str, list[Finding]]` is)
3. At least one Given/When/Then acceptance criterion per requirement
4. At least one negative test case (from inverse thinking or gap analysis)
5. Dependencies reference modules that exist in the inventory or are explicitly marked as "to be built"
6. No circular dependencies in the spec batch

Specs that fail validation are returned to the human with specific errors. The interviewer can re-enter at the relevant question. The legacy ingestion can re-run the gap phase with corrections.

---

## Part 8: MVP vs Full Scope

### MVP (Ship First, Iterate)

The MVP is a single-page web app that proves the hybrid interview pattern works. No integrations, no automation.

| Component | MVP Scope |
|-----------|-----------|
| **Interface** | Single-page form for new project intake |
| **AI** | Ollama (local, no external API dependency) — test qwen3.5 and qwen3-coder for interview quality |
| **Spec output** | File on disk (Markdown) — not Postgres |
| **Factory submission** | Manual — human copies spec to factory input |
| **Review** | Human reviews locally — no review queue |
| **Ingestion** | Not included — new projects only |
| **Auth** | None — single-user, internal tool |
| **Deployment** | Docker Compose on CT alongside Forgejo |

**MVP acceptance criteria:**
- Human can dump an idea into the form
- AI asks follow-up questions via HTMX (no page reload)
- Gharajedaghi checklist tracked and visible as progress bar
- Termination condition fires correctly (3 short answers → propose synthesis)
- SPEC.md + PROD.md generated and downloadable
- End-to-end time: < 30 minutes for a well-scoped feature

### Full Scope (Iterate Toward)

| Component | Full Scope |
|-----------|-----------|
| **Forgejo integration** | Webhooks, PR workflow, `factory-ready` label trigger |
| **Legacy ingestion** | "Ingest Existing Project" with automated SCAN -> CLAIM -> TEST |
| **Factory status** | Live SSE dashboard with pipeline view, failure_ledger, solutions_memory |
| **Review queue** | Approve/reject specs, view factory-produced diffs |
| **Readiness scorecards** | Per-spec and per-project maturity scoring |
| **Multi-user** | API key auth, then SSO, audit log |
| **Regression suite** | Auto-run regression specs on schedule |
| **Spec versioning** | Diff between spec versions, track evolution |

### Iteration Path

```
MVP ──→ +Postgres persistence ──→ +Review queue ──→ +Forgejo integration
                                                            │
                                                            ▼
+Legacy ingestion ──→ +Factory status dashboard ──→ +Multi-user ──→ Full
```

---

## Part 9: Unknowns and Risks

| # | Unknown | Impact | Mitigation | Resolution Needed By |
|---|---------|--------|------------|---------------------|
| 1 | **Best Ollama model for spec questioning** — qwen3.5:35b vs qwen3-coder:30b for interview quality. Coder models may be too narrow; general models may lack technical depth. | AI question quality directly determines spec quality | A/B test: run same 3 project ideas through both models, score output specs on completeness + specificity | Before MVP |
| 2 | **Readiness score threshold** — how do we define "spec is complete enough"? | Too low = garbage specs enter factory. Too high = interviews never terminate. | Start with checklist coverage (all 5 Gharajedaghi properties + typed I/O + acceptance criteria = 100%). Threshold at 80%. Tune based on factory success rate. | Before MVP |
| 3 | **Form vs chat UX balance** — the hybrid approach (form + AI questions) needs testing. Pure chat may be more natural for brainstorming. Pure form may be faster for structured input. | UX determines adoption | MVP starts form-heavy (textarea + HTMX questions). Track where humans switch to chat-like free text. Adjust ratio. | During MVP iteration |
| 4 | **Factory failure escalation** — specs the factory fails on repeatedly. Current failure_ledger captures failures, but no escalation path. | Specs could loop forever in the pipeline | After 3 factory failures on same spec: auto-flag for human review with failure analysis. Human can: rewrite spec, decompose further, or mark as "needs manual implementation". | Before Full scope |
| 5 | **Ollama inference speed for interactive UX** — if AI takes 30+ seconds to generate follow-up questions, the interview UX degrades. | User experience | Streaming responses via SSE. Show "thinking..." indicator. Pre-generate likely follow-up questions while human is typing. Consider smaller model for interview (14b) with larger model for synthesis (35b). | During MVP |

---

## Open Questions

| # | Question | Impact | Status |
|---|----------|--------|--------|
| 1 | ~~Should the interview be CLI-based or web-based?~~ | UX | **RESOLVED: Web portal (FastAPI + HTMX + Tailwind) — see Part 6** |
| 2 | Should legacy ingestion run on the developer's machine or on CT 100? | Infra — some tests require tools only on CT 100 | Open — resolve in implementation |
| 3 | How to handle the 30 compliance frameworks — test all 30 against all target types, or sample? | Scope — 30 * N targets = large test matrix | Open — before Phase 3 execution |
| 4 | Should regression specs auto-run on a schedule (CI) or only on factory cycles? | Ops | Open — after initial ingestion complete |
| 5 | What's the threshold for "partial" vs "broken"? Need a scoring rubric. | Classification consistency | Open — before Phase 3 execution |
| 6 | Which Ollama model for interactive interview? (see Part 9, Unknown #1) | AI quality | Open — before MVP |
| 7 | Readiness score threshold calibration (see Part 9, Unknown #2) | Spec quality gate | Open — before MVP |

---

## Implementation Sequence

This design will go through a plan-then-implement cycle. Suggested phasing:

**Phase A: Tooling**
Build the legacy ingestion scanner (Phase 1: SCAN). This is pure static analysis — no execution, no risk. Produces `inventory.json`. Validates the approach against the real donjon-platform codebase.

**Phase B: Claim + Test**
Build Phase 2 (CLAIM) and Phase 3 (TEST). Deploy donjon-platform to CT 100, run the test battery. This is where we learn what actually works.

**Phase C: Gap + Spec**
Build Phase 4 (GAP) and Phase 5 (SPEC). Produce the first batch of factory-ready specs. Human reviews.

**Phase D: Web Portal MVP**
Build the web portal (Part 6) with MVP scope (Part 8). Single-page interview form, Ollama-backed AI questioning, HTMX dynamic questions, file-based spec output. This replaces Phase D (Interview) from the original plan — the portal IS the interview system. Test with 3 real project ideas to validate the hybrid questioning pattern and calibrate readiness score.

**Phase E: Feedback Loop**
Wire up the re-test cycle (Part 4). Run the first factory spec through the pipeline, re-test, validate the loop works end-to-end.

**Phase F: Portal + Postgres**
Add Postgres persistence to the portal. Review queue. Readiness scorecards. This is the transition from MVP to production.

**Phase G: Forgejo Integration**
Wire up the Forgejo hooks (Part 5). Add "Ingest Existing Project" to the portal. This is last because it's automation of a manual process — get the manual process right first.

**Phase H: Factory Status Dashboard**
Add live pipeline view, failure_ledger display, solutions_memory. SSE-powered. This completes the full scope.
