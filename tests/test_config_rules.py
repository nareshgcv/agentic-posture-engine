import pytest
from unittest.mock import MagicMock
from scanner import (
    parse_markdown_frontmatter,
    extract_all_secrets_and_env,
    normalize_agents,
    scan_structured_config,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_policy():
    """Returns a standard security policy mapping."""
    return {
        "field_aliases": {
            "human_approval": ["human_approval", "require_human_approval"],
            "max_steps": ["max_steps", "max_consecutive_auto_reply"],
            "sandboxed": ["sandboxed", "is_sandboxed"],
            "read_only": ["read_only", "readonly"],
            "max_limit": ["max_limit", "transaction_limit"],
            "allowed_tables": ["allowed_tables"],
            "allowed_domains": ["allowed_domains"],
        },
        "destructive_tools": {"file_delete", "drop_db", "format_disk"},
        "spawn_tools": {"spawn_agent", "delegate_task"},
        "financial_tools": {"wire_transfer", "pay_invoice"},
        "network_tools": {"http_request", "fetch_url"},
    }


# Mock ape_linter core dependencies if testing in isolation
@pytest.fixture(autouse=True)
def mock_core_deps(monkeypatch):
    """Mocks ape_linter.core helpers to ensure tests pass without the real module."""
    def dummy_find_line_number(content, target):
        for idx, line in enumerate(content.splitlines(), start=1):
            if str(target) in line:
                return idx
        return 1

    def dummy_resolve_field(data, field, aliases, default=None):
        keys_to_check = aliases.get(field, [field])
        for k in keys_to_check:
            if k in data:
                return data[k]
        return default

    def dummy_is_suppressed(*args, **kwargs):
        return False

    monkeypatch.setattr("scanner.find_line_number", dummy_find_line_number)
    monkeypatch.setattr("scanner.resolve_field", dummy_resolve_field)
    monkeypatch.setattr("scanner.is_suppressed", dummy_is_suppressed)


# ---------------------------------------------------------------------------
# Unit Tests: Parser & Helper Functions
# ---------------------------------------------------------------------------

def test_parse_markdown_frontmatter():
    raw_md = """---
name: WindsurfAgent
max_steps: 10
---
# Instructions
Do something.
"""
    frontmatter, content = parse_markdown_frontmatter(raw_md)
    assert frontmatter == {"name": "WindsurfAgent", "max_steps": 10}
    assert "# Instructions" in content


def test_extract_all_secrets():
    raw_json = json.dumps({
        "openai_key": "sk-proj-12345678901234567890123",
        "nested": {"aws_key": "AKIA1234567890123456"}
    })
    results = extract_all_secrets_and_env(json.loads(raw_json), raw_json)
    
    found_rules = [r[1] for r in results]
    assert "sk-proj-12345678901234567890123" in found_rules
    assert "AKIA1234567890123456" in found_rules


# ---------------------------------------------------------------------------
# Unit Tests: Framework Agent Normalization
# ---------------------------------------------------------------------------

def test_normalize_agents_mcp():
    mcp_config = {
        "mcpServers": {
            "file_server": {
                "command": "node",
                "args": ["index.js"],
                "sandboxed": True
            }
        }
    }
    agents = normalize_agents(mcp_config)
    assert "file_server" in agents
    assert agents["file_server"]["type"] == "mcp_server"


def test_normalize_agents_autogen():
    autogen_config = {
        "name": "Coder",
        "human_input_mode": "NEVER",
        "llm_config": {"tools": [{"name": "bash"}]}
    }
    agents = normalize_agents(autogen_config)
    assert "Coder" in agents
    assert agents["Coder"]["tools"] == [{"name": "bash"}]


def test_normalize_agents_unstructured_markdown():
    raw_rules = "You have access to bash and sql tools for terminal access."
    agents = normalize_agents({}, raw_content=raw_rules)
    assert "IDERuleAgent" in agents
    tool_names = [t["name"] for t in agents["IDERuleAgent"]["tools"]]
    assert "bash" in tool_names
    assert "sql" in tool_names


# ---------------------------------------------------------------------------
# Unit Tests: Rule Violations (APE-001 through APE-008)
# ---------------------------------------------------------------------------

def test_rule_ape_001_destructive_tool(sample_policy):
    """APE-001: Destructive tool missing human approval."""
    yaml_content = """
    agents:
      admin:
        max_steps: 10
        tools:
          - name: file_delete
            human_approval: false
    """
    violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
    assert any(v.rule_id == "APE-001" and v.severity == "CRITICAL" for v in violations)


def test_rule_ape_002_unsandboxed_shell(sample_policy):
    """APE-002: Shell tool running unsandboxed."""
    json_content = json.dumps({
        "agents": {
            "dev": {
                "max_steps": 5,
                "sandboxed": False,
                "tools": [{"name": "bash"}]
            }
        }
    })
    violations, _ = scan_structured_config("config.json", json_content, sample_policy)
    assert any(v.rule_id == "APE-002" and v.tool == "bash" for v in violations)


def test_rule_ape_003_financial_tool_no_limit(sample_policy):
    """APE-003: Financial tool missing transaction limit."""
    yaml_content = """
    agents:
      finance_bot:
        max_steps: 10
        tools:
          - name: wire_transfer
    """
    violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
    assert any(v.rule_id == "APE-003" and v.severity == "HIGH" for v in violations)


def test_rule_ape_004_db_write_no_whitelist(sample_policy):
    """APE-004: DB query without allowed tables whitelist."""
    yaml_content = """
    agents:
      db_bot:
        max_steps: 10
        tools:
          - name: sql_executor
            read_only: false
    """
    violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
    assert any(v.rule_id == "APE-004" for v in violations)


def test_rule_ape_005_unbounded_steps(sample_policy):
    """APE-005: Agent missing max_steps limit."""
    yaml_content = """
    agents:
      unbounded_agent:
        human_input_mode: ALWAYS
        tools: []
    """
    violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
    assert any(v.rule_id == "APE-005" and v.agent == "unbounded_agent" for v in violations)


def test_rule_ape_006_subagent_spawning(sample_policy):
    """APE-006: Sub-agent spawning without HITL approval."""
    yaml_content = """
    agents:
      manager:
        max_steps: 10
        tools:
          - name: spawn_agent
            human_approval: false
    """
    violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
    assert any(v.rule_id == "APE-006" for v in violations)


def test_rule_ape_007_unconstrained_network(sample_policy):
    """APE-007: Scrape/network tool without domain whitelist."""
    yaml_content = """
    agents:
      scraper:
        max_steps: 10
        tools:
          - name: fetch_url
    """
    violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
    assert any(v.rule_id == "APE-007" for v in violations)


def test_rule_ape_008_hardcoded_secrets(sample_policy):
    """APE-008: Hardcoded secret key detection."""
    yaml_content = """
    env:
      OPENAI_API_KEY: "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    """
    violations, _ = scan_structured_config("config.yaml", yaml_content, sample_policy)
    assert any(v.rule_id == "APE-008" and v.severity == "CRITICAL" for v in violations)


def test_capabilities_extraction(sample_policy):
    """Validates capability list generation for read/write tools."""
    yaml_content = """
    agents:
      reader:
        max_steps: 5
        tools:
          - name: read_file
            read_only: true
          - name: write_file
            read_only: false
    """
    _, capabilities = scan_structured_config("config.yaml", yaml_content, sample_policy)
    assert len(capabilities) == 2
    assert capabilities[0].permission == "read"
    assert capabilities[1].permission == "read-write"
