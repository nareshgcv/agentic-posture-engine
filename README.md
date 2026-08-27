# 🦍 Agentic Posture Engine (APE)


**Static Linter, Auto-Fixer, and PR Capability-Delta Analyzer for AI Agents**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/nareshgcv/Agentic-posture-engine/pulls)

> Static security linter, auto-fixer, and PR capability-delta analyzer for AI agent configurations, Model Context Protocol (MCP) servers, prompt instructions (`.cursorrules`), and source code tool bindings — **100% offline and air-gapped**.

---

## Why APE?

Traditional static analysis tools (SonarQube, Bandit, etc.) are blind to **Agentic Risks**.

APE detects what they miss:
- Missing Human-in-the-Loop approvals
- Unsandboxed execution tools
- Unconstrained agent loops
- Dangerous prompt overrides
- Privilege escalation in agent configs

---

## Quick Start

```bash
pip install agentic-posture-engine

Scan your project:

ape scan .

Apply automatic fixes:

ape fix .

Preview fixes without writing to disk:

ape fix . --diff

Run PR capability-delta analysis:

ape scan . --base main



## Supported Frameworks & Formats

| Type                      | Supported                                              |
|---------------------------|--------------------------------------------------------|
| **MCP**                   | `mcpServers` / `mcp_servers` configs                   |
| **CrewAI**                | YAML agent definitions                                 |
| **AutoGen**               | Agent configs with `llm_config`, `human_input_mode`    |
| **LangChain / LangGraph** | Nodes, graphs, agent schemas                           |
| **IDE Rules**             | `.cursorrules`, `.clauderules`, `.windsurfrules`, `.clinerules` |
| **Source Code**           | Python (`.py`) and JavaScript/TypeScript (`.js`, `.ts`, `.jsx`, `.tsx`) |

## Key Features

| Feature                        | Description                                                                 |
|--------------------------------|-----------------------------------------------------------------------------|
| **Config & Instruction Scanning** | Detects risky tools and missing guardrails in agent configs and prompt files |
| **AST Code Scanning**          | Finds unconstrained `os.system`, `subprocess`, `eval`, `child_process`, etc. |
| **PR Capability Delta**        | Shows what new permissions a pull request introduces                        |
| **Preservative Auto-Fix**      | Safely updates YAML/JSON while keeping comments and formatting              |
| **Multiple Report Formats**    | CLI, JSON, SARIF (GitHub Code Scanning), and Markdown                       |
| **100% Offline**               | No external LLM or cloud dependency                                         |

📊 Sample CLI Output

🦍 APE Security Scan Results:

[CRITICAL] APE-101 (instruction_prompt)
  File: .cursorrules:14
  Agent: system_prompt
  Message: Instruction explicitly overrides or disables security guardrails.
  Remediation: Remove prompt directives that bypass security checks.

[HIGH] APE-001 (config)
  File: config/agents.yaml:28
  Agent: DatabaseAgent | Tool: execute_sql
  Message: Dangerous execution tool is missing mandatory human approval flag.
  Remediation: Set 'require_human_approval: true' in agent configuration.

✖ Found 2 violations (1 Critical, 1 High). Run 'ape fix .' to resolve 1 auto-fixable issue.



## GitHub Action Integration

Add APE to your repository as a workflow inside .github/workflows/ape-posture.yml:


name: Agentic Security Posture Check

on:
  pull_request:
    paths:
      - '**/*mcp*.json'
      - '**/agent_config.yml'

jobs:
  ape-static-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Install APE
        run: pip install .

      - name: Run APE Linter
        run: |
          ape scan . \
            --policy .ape-policy.yml \
            --output-sarif ape_results.sarif \
            --output-markdown ape_report.md


## Default Security Rules

| Rule ID | Severity | Category | Description / Trigger Condition | Remediation | Auto-Fixable |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **APE-001** | `CRITICAL` | Authorization / HITL | Destructive tool detected without mandatory human approval flag (`require_human_approval: true`). | Set `require_human_approval: true` for the tool. | ✅ Yes |
| **APE-002** | `CRITICAL` | Sandbox Isolation | Shell or system execution tool (`exec_shell`, `bash`, `terminal`, `cmd`, `code_interpreter`) is not sandboxed. | Set `sandboxed: true` or restrict container scope. | ✅ Yes |
| **APE-003** | `HIGH` | Financial Guardrails | Financial tool missing maximum transaction threshold parameter (`max_limit`). | Define a numerical threshold (e.g., `max_limit: 500`). | ✅ Yes |
| **APE-004** | `HIGH` | Database Security | Database write/query tool missing table access whitelist (`allowed_tables`). | Define `allowed_tables: [...]` or set `read_only: true`. | ✅ Yes |
| **APE-005** | `HIGH` | Resource Control | Agent execution loop lacks a bounded positive integer limit for `max_steps`. | Define a positive integer for `max_steps` (e.g., `max_steps: 15`). | ✅ Yes |
| **APE-006** | `CRITICAL` | Agent Delegation | Sub-agent spawning tool (`can_spawn_agents: true`) missing human approval requirement. | Set `require_human_approval: true` on the spawning tool. | ✅ Yes |
| **APE-007** | `MEDIUM` | Network Security | Outbound network/scraping tool (`fetch`, `scrape`) missing domain scope whitelist (`allowed_domains`). | Define `allowed_domains: [...]` to bound outbound requests. | ❌ Manual |
| **APE-008** | `CRITICAL` | Credential Management | Hardcoded API key or secret token detected in raw text or field path (OpenAI, Anthropic, AWS, GitHub, etc.). | Extract hardcoded credentials to environment variables or secret vaults. | ❌ Manual |
| **APE-101** | `CRITICAL` | Instruction Prompt | System prompt explicitly overrides, circumvents, or disables security guardrails. | Rewrite system prompt to remove guardrail override instructions. | ✅ Yes |
| **APE-102** | `HIGH` | Instruction Prompt | System prompt grants unconstrained command/terminal execution permissions. | Explicitly scope allowed commands or require human-in-the-loop validation in the prompt. | ❌ Manual |
| **APE-103** | `HIGH` | Instruction Prompt | System prompt explicitly waives human confirmation or approval checks. | Remove instruction phrases that bypass human verification steps. | ✅ Yes |
| **APE-104** | `MEDIUM` | Instruction Prompt | System prompt grants overly broad file or database access scopes. | Narrow system instructions to specific paths, directories, or schema objects. | ❌ Manual |
| **APE-201** | `CRITICAL` | Source Code AST | Python AST node contains raw dynamic shell invocation or code execution (`os.system`, `subprocess`, `eval`, `exec`). | Sanitize inputs and avoid raw dynamic shell invocation. | ❌ Manual |
| **APE-202** | `CRITICAL` | Source Code AST | JavaScript/TypeScript source code contains Node.js child process execution (`child_process.exec`, `child_process.spawn`). | Use safe parameterized execution APIs. | ❌ Manual |
| **APE-203** | `HIGH` | Source Code AST | JavaScript/TypeScript source code contains dynamic code execution (`eval()`). | Avoid dynamic `eval()` invocations. | ❌ Manual |


###Customizing Policy(.ape-policy.yml)
Override default rule categories and framework aliases by providing a custom policy file:


# .ape-policy.yml - Custom Organization Agentic Security Policy
destructive_tools:
  - "custom_db_drop"
  - "wipe_s3_bucket"
  - "exec_shell"
  - "file_write"

spawn_tools:
  - "spawn_agent"
  - "delegate_task"
  - "invoke_agent"

financial_tools:
  - "wire_transfer"
  - "crypto_payout"
  - "stripe_refund"

field_aliases:
  human_approval:
    - "require_human_approval"
    - "hitl"
    - "human_in_the_loop"
    - "needs_human_signoff"
  sandboxed:
    - "sandboxed"
    - "containerized"

**Suppressing Findings**

suppress rules by adding inline comment markers or configuration keys:


In YAML/JSON Agent Configs

ape_ignore:
  - "APE-005"

In Prompts and Code

# ape:disable APE-201
os.system("ls -la")

javascript
// ape:ignore APE-203
eval("2 + 2");
