# AI SOC Team: Autonomous Security Operations with VS Code Custom Agents

An experimental framework for autonomous security operations using VS Code Custom Agents, KQL-Search-MCP, and Microsoft Sentinel MCP. Four specialized AI agents work together to investigate alerts, hunt threats, build detections, and respond to incidents.

## What This Is

This project demonstrates how to orchestrate Model Context Protocol (MCP) servers through VS Code custom agents to create an autonomous Security Operations Centre team. Rather than manually searching for queries, running investigations, and documenting findings, the agents handle the mechanical work while you focus on analysis and decision-making.

## Limitations & Reality Checks

### What This Is Not
- ❌ Production-ready SOC replacement
- ❌ Fully autonomous (requires human oversight)
- ❌ Perfect (agents make mistakes and need supervision)
- ❌ A solution to all SOC problems
- ❌ Going to investigate alerts while you're on holiday (don't even think about it)
- ❌ A replacement for actually understanding what the queries do
- ❌ Going to stop your CEO clicking phishing links
- ❌ Able to explain to management why you need more budget
- ❌ A way to avoid learning KQL (sorry)

### Known Issues
- Agents sometimes search for tables that don't exist in your workspace
- Query adaptation can introduce errors
- False positive tuning requires human judgment
- Handoff context can be verbose
- Agents occasionally cite non-existent GitHub repos
- Performance depends heavily on Claude model quality

### What It Actually Is
- ✅ An experiment in tool orchestration
- ✅ A way to explore autonomous agent capabilities
- ✅ A demonstration of MCP server coordination
- ✅ A practical time-saver for investigation mechanics
- ✅ An interesting approach to using tools we already have

**What makes this interesting:** It's not just about AI answering questions - these agents actively use tools, make decisions, and hand off work to each other based on investigation findings.

## The Team

### 🔍 SOC Analyst
**Role:** First-line alert triage and investigation  
**Autonomy:** Lists incidents, retrieves details, investigates entities, enriches IOCs, makes triage decisions  
**Handoffs:** Escalates to Threat Hunter for deep investigation, Detection Engineer for detection gaps, or Incident Responder for confirmed threats

### 🎯 Threat Hunter  
**Role:** Proactive threat hunting and hypothesis testing  
**Autonomy:** Verifies table availability, searches for hunting queries, executes hunts across Defender/Sentinel data, investigates entities found, validates findings  
**Handoffs:** Passes threats to Incident Responder, detection gaps to Detection Engineer, or findings back to SOC Analyst

### 🛡️ Detection Engineer
**Role:** Build and optimise detection rules  
**Autonomy:** Verifies tables exist, searches for detection patterns, tests against historical data, checks prevalence, validates queries  
**Handoffs:** Sends detections to Threat Hunter for validation, to Incident Responder for playbooks, or to SOC Analyst for operational review

### 🚨 Incident Responder
**Role:** Containment, eradication, and recovery  
**Autonomy:** Gets incident details, investigates affected entities, maps lateral movement, checks vulnerabilities, tracks remediation  
**Handoffs:** Requests scope expansion from Threat Hunter, detection improvements from Detection Engineer, or case closure from SOC Analyst

## The Tools

### KQL-Search-MCP
**Purpose:** Search and work with KQL queries across GitHub  
**Capabilities:**
- 32 tools for searching, validating, and generating KQL queries
- Indexes 330+ table schemas from Sentinel, Defender XDR, and Azure Monitor
- Searches thousands of queries across Microsoft and community repositories
- Validates queries against actual table schemas
- Generates queries from natural language

**VSCode Marketplace:** https://marketplace.visualstudio.com/items?itemName=noodlemctwoodle.kql-search-mcp  
**npm:** https://www.npmjs.com/package/kql-search-mcp

### Microsoft Sentinel MCP

**Data Exploration Collection:**
- `list_sentinel_workspaces` - List accessible workspaces
- `search_tables` - Find tables in Sentinel data lake
- `query_lake` - Execute KQL against Sentinel data lake
- Entity analyzers for users, URLs, IPs

**Triage Collection:**
- `ListIncidents` / `GetIncidentById` - Incident management
- `ListAlerts` / `GetAlertById` - Alert investigation
- `RunAdvancedHuntingQuery` - Hunt across Defender tables
- `FetchAdvancedHuntingTablesOverview` - Discover available tables
- User/device/file/IP investigation tools
- Vulnerability and remediation tracking

**Setup:** https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-get-started

## How It Works

### The Workflow

1. **User provides an alert or incident**
2. **SOC Analyst investigates:**
   - Gets incident details via `sentinel-triage`
   - Investigates entities (users, devices, files, IPs)
   - Searches for investigation queries via `kql-search`
   - Executes queries against Sentinel/Defender data
   - Enriches IOCs with threat intelligence
   - Makes triage decision

3. **Agent decides next action:**
   - Close (false positive with evidence)
   - Investigate further (needs more data)
   - Escalate to specialist (confirmed threat)

4. **Autonomous handoff with full context:**
   - Threat Hunter receives hypothesis and entities
   - Detection Engineer receives threat details and TTPs
   - Incident Responder receives affected systems and IOCs

5. **Specialists continue investigation:**
   - Use same tool ecosystem
   - Build on previous findings
   - Can hand off to other agents as needed

### Key Design Principles

**1. Agents DO the work, don't just suggest it**
- "I will call this tool" not "You should use this tool"
- Active voice, clear instructions
- Tools are invoked automatically

**2. Always verify before executing**
- Check tables exist before querying (`FetchAdvancedHuntingTablesOverview`)
- Get schemas before using columns (`FetchAdvancedHuntingTablesDetailedSchema`)
- Validate queries before running (`validate_kql_query`)
- No BadRequest errors from non-existent tables

**3. Never write KQL from scratch**
- Always search for existing queries first (`kql-search`)
- Use proven community patterns
- Adapt rather than create

**4. Autonomous handoffs**
- `send: true` - Agents hand off automatically
- `infer: true` - Agents can call each other as subagents
- Full context passed in handoff prompts

## Setup

### Prerequisites
- VS Code with GitHub Copilot
- Microsoft Sentinel or Defender XDR access

### Step 1: Install Extensions and Configure MCP Servers

**1. Install KQL-Search-MCP Extension:**
- Open VS Code Extensions (Ctrl+Shift+X / Cmd+Shift+X)
- Search for "KQL-Search-MCP"
- Click "Install"

**2. Install Microsoft Sentinel MCP Extension:**
- Open VS Code Extensions
- Search for "Microsoft Sentinel MCP"
- Click "Install"
- Authenticate with your Azure credentials when prompted
- This provides the Data Exploration collection (query_lake, search_tables, etc.)

**3. Add Sentinel Triage Collection Manually:**

The Triage collection is not included in the extension and must be added manually:

- Open VS Code settings
- Search for "MCP Servers"
- Add a new server configuration:

```json
{
  "Sentinel Triage": {
    "url": "https://sentinel.microsoft.com/mcp/triage",
    "type": "http"
  }
}
```

- Authenticate when prompted (use same Azure credentials)

### Step 2: Add Custom Agents

Place the four agent markdown files in your VS Code workspace:
- `soc-analyst.agent.md`
- `threat-hunter.agent.md`
- `detection-engineer.agent.md`
- `incident-responder.agent.md`

### Step 3: Configure Agent Tools

Each agent's YAML header should include:

```yaml
---
description: [Agent description]
name: [Agent Name]
argument-hint: [What to tell this agent]
tools: ['kql-search/*', 'microsoft-sentinel/*', 'sentinel-triage/*', 'search', 'web/fetch', 'web/githubRepo']
infer: true
handoffs:
  - label: [Handoff Label]
    agent: [Target Agent Name]
    prompt: [Context to pass with handoff]
    send: true
---
```

## Usage Examples

### Basic Investigation
```
User: Investigate incident INC-12345

SOC Analyst:
→ Calls GetIncidentById
→ Lists affected user alerts
→ Searches for investigation queries
→ Executes queries against Sentinel
→ Checks IP reputation
→ Decides: "Confirmed compromise - escalating"
→ Auto-hands off to Incident Responder

Incident Responder:
→ Receives incident context
→ Investigates device vulnerabilities
→ Maps lateral movement
→ Provides containment plan
```

### Threat Hunting
```
User: Hunt for Kerberoasting attacks

Threat Hunter:
→ Verifies tables exist (FetchAdvancedHuntingTablesOverview)
→ Gets schemas (FetchAdvancedHuntingTablesDetailedSchema)
→ Searches for hunting queries (kql-search)
→ Executes hunt (RunAdvancedHuntingQuery)
→ Investigates suspicious accounts found
→ Finds evidence
→ Hands off to Detection Engineer

Detection Engineer:
→ Receives hunt findings
→ Searches for detection patterns
→ Tests against historical data
→ Validates query
→ Creates production-ready detection rule
```

### Detection Development
```
User: Create detection for credential dumping

Detection Engineer:
→ Verifies tables exist
→ Gets table schemas
→ Searches for credential dumping queries
→ Tests against 30 days historical data
→ Checks file prevalence for false positives
→ Validates query syntax
→ Hands off to Threat Hunter for validation

Threat Hunter:
→ Receives detection query
→ Hunts for instances in environment
→ Validates detection quality
→ Reports findings back
```

## What Makes This Work

### Technical Implementation

**1. Tool Syntax in Agent Prompts**
- Wildcards in YAML: `tools: ['kql-search/*', 'microsoft-sentinel/*']`
- Specific names in content: `#tool:kql-search/search_kql_queries`
- Never generic references like `#tool:search` for threat intel

**2. Handoff Configuration**
```yaml
handoffs:
  - label: Hunt for Threats
    agent: Threat Hunter
    prompt: Hunt for related threats. Alert details, entities, IOCs provided above.
    send: true  # Auto-handoff without asking
```

**3. Agent Behavior**
Agents actively use tools:
```markdown
I will call #tool:sentinel-triage/GetIncidentById
I will search for queries with #tool:kql-search/search_kql_queries
I will execute with #tool:sentinel-triage/RunAdvancedHuntingQuery
```

Not passive suggestions:
```markdown
❌ You should use kql-search to find queries
✅ I will call #tool:kql-search/search_kql_queries to find queries
```

### Critical Design Choices

**Always Verify Before Execute:**
The agents learned this the hard way - trying to query non-existent tables (`IdentityQueryEvents`) resulted in BadRequest errors. Now they:
1. Verify tables exist first
2. Get schemas to check columns
3. Only then execute queries

**Never Write KQL From Scratch:**
With 32 KQL-Search-MCP tools and thousands of community queries, there's no reason to write KQL manually. The agents search, adapt, and validate.

**Context Over Everything:**
Handoffs include full context from previous investigation. The receiving agent doesn't start fresh - they continue where the previous agent left off.

## Why This Matters

**Problem:** Security analysts spend 60-80% of their time on mechanical tasks - searching for queries, running them, copying results, looking up IOCs, documenting findings. The actual analysis is maybe 20% of the work.

**This Approach:** Let agents handle the mechanical 80% (searching, executing, enriching) so analysts can focus on the analytical 20% (making decisions, understanding threats, strategic thinking).

**Not Replacing Analysts:** The agents aren't smarter than experienced security professionals. They're just tireless at doing the boring bits and better at remembering which tool to use when.

## The Experiment

I built KQL-Search-MCP to stop googling "SigninLogs query" for the 50th time. Microsoft built Sentinel MCP to make security data accessible. Neither of us were thinking about autonomous agents.

Then I wondered: what if these tools could work together without me orchestrating every step? What if an AI agent could decide "I need to verify this table exists, then search for a query, then execute it against live data, then check threat intelligence"?

Turns out, they can. And it's genuinely useful, even if it took two hours to debug why they kept trying to query tables that didn't exist.

## Contributing

This is an experimental project. If you find it useful or interesting:
- Share your agent configurations
- Report what works (and what doesn't)
- Suggest improvements to agent prompts
- Document your use cases

The agents are just markdown files with YAML headers. Fork them, adapt them, improve them.

## License

MIT License - use it however you want.

## Acknowledgements

- **Microsoft** - For building Sentinel MCP and making security data accessible
- **Anthropic** - For the MCP specification
- **VS Code Team** - For custom agents and GitHub Copilot
- **Security Community** - For thousands of detection rules and hunting queries that make this possible

## Links

- **KQL-Search-MCP:** https://www.npmjs.com/package/kql-search-mcp
- **Sentinel MCP Docs:** https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-get-started
- **Blog Post:** https://sentinel.blog/becoming-the-puppet-master-of-ai-soc-analysts
- **My Blog:** https://sentinel.blog

---

**Built by [@noodlemctwoodle](https://github.com/noodlemctwoodle) | Powered by curiosity, too much coffee and not enough sleep ☕**