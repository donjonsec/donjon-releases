# Dark Factory — MetaClaw-Inspired Self-Learning Evolution

**Date:** 2026-03-21
**Status:** Draft
**Authors:** Cris + Claude
**Reference:** [MetaClaw: Just Talk — An Agent That Meta-Learns and Evolves in the Wild](https://arxiv.org/abs/2603.17187) (Xia et al., 2026)
**Related:** `/opt/darkfactory/specs/factory-validation-upgrade.md`, SDD Ingestion Design

---

## Problem

The Dark Factory produces code through a 5-plane pipeline (dev → validation → security → release → staging). When code fails validation, the foreman retries with fix hints from `solutions_memory`. But:

1. **The factory doesn't learn proactively.** It only records solutions when a retry succeeds. It never analyzes failure patterns across runs to synthesize preventive rules.
2. **Solutions aren't injected into generation.** The 13 solutions in memory are queried on failure, but never proactively fed to the dev agent before it generates code. The dev agent makes the same mistakes repeatedly.
3. **The factory is static between runs.** No self-improvement happens during idle time. The Ollama models never get fine-tuned on the factory's own successful outputs.
4. **Skills don't compound.** Individual fixes ("split subprocess args," "don't use emoji in ASCII art") aren't combined into higher-level rules ("always validate external tool integration patterns").

MetaClaw (Xia et al., 2026) solves these problems with two mechanisms: **skill-driven fast adaptation** (immediate learning from failures) and **opportunistic policy optimization** (gradient-based improvement during idle windows). This spec adapts both to the Dark Factory.

---

## Architecture: MetaClaw Applied to Dark Factory

```
                    ┌─────────────────────────────────┐
                    │         SKILL LIBRARY            │
                    │  (solutions_memory + rules)      │
                    │                                  │
                    │  "Never use emoji in ASCII art"  │
                    │  "Split subprocess args"         │
                    │  "Parse URLs before CLI flags"   │
                    │  "Check tool availability first"  │
                    └──────┬──────────────┬────────────┘
                           │              │
                    inject │              │ synthesize
                    before │              │ from failures
                    gen    │              │
                           ▼              │
              ┌────────────────────┐      │
              │    DEV AGENT       │      │
              │  (code generation) │      │
              └────────┬───────────┘      │
                       │                  │
                       ▼                  │
              ┌────────────────────┐      │
              │  VALIDATION PLANE  │      │
              │  (lint + type +    │      │
              │   functional test) │      │
              └────────┬───────────┘      │
                       │                  │
                  ┌────┴────┐             │
                  ▼         ▼             │
               PASS       FAIL ──────────┘
                  │         │
                  │         └──→ failure_ledger
                  │                   │
                  ▼                   │
           ┌──────────┐              │
           │ STAGING  │              │
           └────┬─────┘              │
                │                    │
                ▼                    │
          ┌──────────────┐           │
          │ IDLE TIME    │◄──────────┘
          │ OPTIMIZER    │
          │              │
          │ • Cluster    │
          │   failures   │
          │ • Synthesize │
          │   rules      │
          │ • LoRA fine- │
          │   tune model │
          └──────────────┘
```

---

## Phase 1: Skill Injection (Immediate — 1-2 hours)

### What

Before the dev agent generates code, inject all relevant solutions from `solutions_memory` as context. The dev agent receives not just the contract spec but also "lessons learned" from prior failures.

### How

Modify `foreman.py` → `run_plane("dev", ...)`:

1. Before dispatching to dev-agent, query `solutions_memory` for patterns matching the contract's module path, dependencies, or error signatures from prior runs of similar contracts.
2. Add a `learned_rules` field to the dev agent's input payload containing the relevant solutions.
3. The dev agent's prompt template includes these rules as "DO NOT" constraints.

### Acceptance Criteria

```
Given a contract for a module that previously failed with "subprocess arg splitting"
When the dev agent generates code for a new module that uses subprocess
Then the generated code uses list arguments (not space-separated strings)
And the learned rule "Always split subprocess command arguments" appears in the agent's input

Given a contract for a TUI module
When the dev agent generates code that includes ASCII art
Then the generated code uses text characters, not emoji
And the learned rule "Never use emoji in fixed-width ASCII art" appears in the agent's input

Given no prior failures for a contract's domain
When the dev agent generates code
Then the learned_rules field is empty (no false constraints injected)
```

### Implementation

```python
# In foreman.py, before run_plane("dev", ...):
async def _get_relevant_skills(self, contracts: list[Contract]) -> list[dict]:
    """Query solutions_memory for rules relevant to these contracts."""
    skills = []
    for contract in contracts:
        # Match by module path patterns
        solutions = await self._db.find_solutions_by_pattern(
            module_pattern=contract.module,
            limit=10,
        )
        # Match by dependency overlap
        for dep in contract.dependencies:
            dep_solutions = await self._db.find_solutions_by_pattern(
                module_pattern=dep,
                limit=5,
            )
            solutions.extend(dep_solutions)
        skills.extend(solutions)
    # Deduplicate by error_signature
    seen = set()
    unique = []
    for s in skills:
        sig = s.get("error_signature", "")
        if sig not in seen:
            seen.add(sig)
            unique.append(s)
    return unique
```

### Database Addition

```sql
-- New method in db.py
async def find_solutions_by_pattern(self, module_pattern: str, limit: int = 10):
    """Find solutions with fix_patterns relevant to a module path."""
    async with self._pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT error_signature, problem, fix_pattern, reliability_score
            FROM solutions_memory
            WHERE quarantined = false
              AND reliability_score >= 0.5
              AND (
                fix_pattern::text ILIKE '%' || $1 || '%'
                OR products_affected @> ARRAY[$2]
              )
            ORDER BY reliability_score DESC
            LIMIT $3
        """, module_pattern, 'donjon-platform', limit)
        return [dict(r) for r in rows]
```

---

## Phase 2: Failure Trajectory Analysis (1-2 hours)

### What

After a pipeline run completes (pass or fail), analyze the full trajectory:
- What contracts were attempted?
- What errors occurred?
- What retry patterns emerged?
- Are there clusters of similar failures?

Synthesize new rules from failure clusters.

### How

Add a `post_pipeline_analysis` method to the foreman that runs after every pipeline completion:

1. Query `failure_ledger` for failures from this run.
2. Group by `error_signature` prefix (e.g., all `validation::*` failures).
3. For each cluster with 3+ occurrences, check if a solution exists.
4. If no solution exists, generate one using the LLM:
   - Feed the cluster's failure reports to Claude/Ollama
   - Ask: "What common pattern caused these failures? What rule would prevent them?"
   - Store the synthesized rule in `solutions_memory`

### Acceptance Criteria

```
Given the factory has 9 "validation::lint" failures in the ledger with no solution
When post_pipeline_analysis runs
Then it identifies the cluster and synthesizes a rule
And the rule is stored in solutions_memory with reliability_score 0.5 (untested)

Given a synthesized rule with reliability_score 0.5
When the rule is applied to a new contract and the contract passes validation
Then the rule's reliability_score increases to 0.8

Given a synthesized rule that leads to a failure
When the failure is recorded
Then the rule's reliability_score decreases
And if it drops below 0.3, the rule is quarantined
```

---

## Phase 3: Opportunistic Idle-Time Optimization (4-8 hours)

### What

MetaClaw's OMLS (Opportunistic Meta-Learning Scheduler) triggers learning during user-inactive windows. For the Dark Factory:

1. **Monitor inactivity** — No pipeline runs for 30+ minutes.
2. **Trigger analysis** — Review failure_ledger, cluster patterns, synthesize rules.
3. **Optional: LoRA fine-tuning** — Take successful code generations and fine-tune the local Ollama model.

### How

A systemd timer or cron job on CT 100 that:

1. Checks if any factory pipeline is running (query governor active count).
2. If idle for 30+ minutes, runs the failure trajectory analysis.
3. If idle for 2+ hours and GPU available, triggers LoRA fine-tuning.
4. Logs all learning activity to an `evolution_log` table.

### Acceptance Criteria

```
Given the factory has been idle for 30 minutes
When the OMLS scheduler triggers
Then it runs post_pipeline_analysis on all unanalyzed failures
And any new rules are logged to solutions_memory

Given the factory is processing a pipeline
When the OMLS scheduler checks
Then it does NOT trigger (no interference with active work)

Given the OMLS has synthesized 5 new rules since last run
When the next pipeline processes a contract matching those rules
Then the dev agent receives the rules as context
And the pass rate improves compared to pre-rule runs
```

### Implementation

```python
# /opt/darkfactory/services/omls_scheduler.py
"""Opportunistic Meta-Learning Scheduler — learns during idle time."""

import asyncio
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class OMLS:
    def __init__(self, db, governor, analyzer, check_interval=300):
        self._db = db
        self._governor = governor
        self._analyzer = analyzer
        self._check_interval = check_interval  # seconds
        self._last_activity = datetime.utcnow()

    async def run(self):
        """Main loop — check for idle time, trigger learning."""
        while True:
            await asyncio.sleep(self._check_interval)

            if self._governor.active_count > 0:
                self._last_activity = datetime.utcnow()
                continue

            idle_minutes = (datetime.utcnow() - self._last_activity).seconds / 60

            if idle_minutes >= 30:
                logger.info("Idle %.0f min — running failure analysis", idle_minutes)
                await self._analyzer.analyze_unprocessed_failures()

            if idle_minutes >= 120:
                logger.info("Idle %.0f min — running skill synthesis", idle_minutes)
                await self._analyzer.synthesize_compound_skills()
```

---

## Phase 4: Compound Skill Synthesis (2-4 hours)

### What

Individual rules are useful but compound skills are more powerful. MetaClaw shows that skills compound — "check tool availability" + "handle missing tools gracefully" + "show progress during long operations" = a composite skill for any new scanner contract.

### How

1. Cluster solutions by affected module type (scanner, TUI handler, API endpoint, export format).
2. For each cluster, synthesize a compound rule that combines all individual rules.
3. Store compound skills with a `parent_rules` field linking to the individual solutions.

### Example

```
Individual rules:
  1. "Split subprocess command arguments into list elements"
  2. "Check tool availability with shutil.which before calling"
  3. "Add timeout to all subprocess.run calls"
  4. "Handle missing tools with clear error message, not crash"

Compound skill: "External Tool Integration Pattern"
  When generating code that calls external tools (nmap, nikto, nuclei, etc.):
  1. Check availability: shutil.which(tool_name)
  2. Handle missing: clear error message with install instructions
  3. Build command: list elements, never space-separated strings
  4. Execute: subprocess.run with timeout, capture_output=True
  5. Parse output: handle empty stdout, check returncode
  6. Report: show progress before, results after
```

### Database Addition

```sql
CREATE TABLE compound_skills (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    pattern JSONB NOT NULL,  -- The compound rule
    parent_rules UUID[],     -- Links to solutions_memory entries
    applicability TEXT[],    -- Module types this applies to: scanner, tui, api, export
    reliability_score FLOAT DEFAULT 0.5,
    times_applied INT DEFAULT 0,
    times_succeeded INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT now()
);
```

---

## Phase 5: LoRA Fine-Tuning Pipeline (Long-term, 1-2 days)

### What

Take the factory's successful code generations (contracts that passed all 5 planes) and fine-tune the local Ollama model on them. The factory's own output becomes training data for itself.

### How

1. Export successful contract → code pairs from the factory's history.
2. Format as instruction-following training data: `{"instruction": contract_spec, "output": generated_code}`.
3. Use `ollama create` with a Modelfile that applies LoRA adapters.
4. Run during extended idle windows (overnight, weekends).
5. A/B test: run the same contract through the base model and the fine-tuned model, compare pass rates.

### Constraints

- Quadro P400 (2GB VRAM) on CT 100 is insufficient for LoRA training — CPU-only or use cloud.
- Training data must be versioned and separated from test data (MetaClaw's versioning mechanism).
- Never auto-deploy a fine-tuned model — human approval required.

### Acceptance Criteria

```
Given 50+ successful contract-code pairs in the factory history
When LoRA fine-tuning runs on qwen2.5-coder:14b
Then a fine-tuned model variant is created: qwen2.5-coder:14b-factory-v1

Given the fine-tuned model
When tested on 10 held-out contracts
Then it achieves >= 80% first-pass success rate (vs ~60% for base model)

Given the fine-tuned model passes A/B testing
When Cris approves deployment
Then the factory config switches to the fine-tuned model
And the base model is retained as fallback
```

---

## Implementation Sequence

| Phase | Effort | Dependencies | Impact |
|-------|--------|-------------|--------|
| **1: Skill Injection** | 1-2 hours | None | Immediate — dev agent stops making known mistakes |
| **2: Failure Trajectory Analysis** | 1-2 hours | Phase 1 | High — factory learns from patterns, not just individual failures |
| **3: OMLS Scheduler** | 4-8 hours | Phase 2 | Medium — continuous improvement during idle time |
| **4: Compound Skills** | 2-4 hours | Phase 2 | Medium — higher-level rules improve generation quality |
| **5: LoRA Fine-Tuning** | 1-2 days | Phase 1-4 + training infra | High — model itself improves, not just context |

**Start with Phase 1.** It's the highest-impact, lowest-effort change. The factory already has 13 solutions — injecting them as context costs nothing and prevents known mistakes immediately.

---

## Metrics

Track these to measure whether the factory is actually learning:

| Metric | Baseline (now) | Target (after Phase 1-2) | Target (after Phase 3-5) |
|--------|---------------|-------------------------|-------------------------|
| First-pass validation success | ~40% | 60% | 80% |
| Solutions in memory | 13 | 30+ | 100+ |
| Compound skills | 0 | 5+ | 20+ |
| Avg retries per contract | ~2 | 1.5 | 0.5 |
| Unique error signatures | 20+ | 20+ (same, but handled) | 10 (prevented) |

---

## Open Questions

| # | Question | Impact |
|---|----------|--------|
| 1 | Should skill injection use vector similarity (embeddings) or keyword matching? | Phase 1 implementation |
| 2 | How to prevent skill injection from over-constraining the dev agent? | Too many "DON'T" rules may reduce creativity |
| 3 | LoRA training data — include only PASS contracts or also FAIL→PASS retry pairs? | Phase 5 data quality |
| 4 | Should the OMLS scheduler run on CT 100 or a dedicated CT? | Phase 3 infrastructure |
| 5 | How to measure skill impact — A/B test with and without skills? | All phases |
