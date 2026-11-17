# ASO Security: Fail-Closed Protection for AI Agents

ASO is a Python security orchestration library for AI agents, memory systems, tool execution, and secrets. It gives developers a structured, fail-closed boundary for protecting agent workloads before they reach privileged resources.

ASO is designed for projects where an agent can read/write memory, call tools, and access credentials. In those environments, a single prompt classifier is not enough. ASO adds an explicit decision layer that inspects intent, validates context, authorizes access, and quarantines suspicious activity before execution continues.

Source code: [ASO on GitHub](https://github.com/AyoubStudent/ASO)

## Why ASO exists

Modern AI agents often need to:

- read and write memory
- call external tools
- retrieve credentials and tokens
- work with multi-step task flows
- operate in enterprise or production contexts

Without a hardened security boundary, these operations can be abused by prompt injection, unsafe tool invocation, model misalignment, or untrusted memory content.

ASO helps by enforcing a clear policy:

- inspect the request
- validate trusted host context
- authorize the requested resource
- execute only through guarded gateways
- deny or quarantine when the request is suspicious

## Core idea

ASO separates concerns into different application layers:

- Prompt inspection and intent analysis
- Central orchestration and decision handling
- Memory protection
- Tool execution protection
- Secret and credential access control

This design keeps security decisions auditable and avoids trusting agent-controlled request data as proof of authorization.

## Installation

```bash
pip install aso-security
```

The base package includes runtime dependencies such as Pydantic and SQLAlchemy. Install the model integrations your application uses:

```bash
python -m pip install "aso-security[openai]"
python -m pip install "aso-security[google]"
python -m pip install "aso-security[huggingface]"
python -m pip install "aso-security[ollama]"
python -m pip install "aso-security[langchain]"
```

For all listed model integrations, install `aso-security[all]`. Memory-provider SDKs are separate extras such as `aso-security[memory-qdrant]` or `aso-security[memory-postgresql]`; `aso-security[memory-all]` installs the available memory SDK set. These extras do not install the database services themselves.

```bash
python -m pip install "aso-security[all]"
python -m pip install "aso-security[memory-qdrant]"
python -m pip install "aso-security[memory-all]"
```

## Start here

ASO offers standalone guard services and a unified orchestrator. It does not automatically intercept framework tool calls, memory, or secret use; the host application must send each protected operation through a guard.

| Service | Main entry point | What it does |
| --- | --- | --- |
| PromptGuard | `PromptAnalyser.inspect(...)`, `analyse(...)`, `decision(...)` | Extracts features and optionally returns a model-backed prompt decision. |
| MemoryGuard | `GuardedMemoryAccessLayer.execute(request, context)` | Authorizes a registered store operation, invokes its adapter, inspects retrieved data, and audits the result. |
| ToolGuard | `ToolRegistry`, `ToolGuard.execute(...)`, `create_framework_tool(...)` | Registers developer-owned callables, guards execution and output, and records encrypted audit events. |
| SecretGuard | `SecretBroker.register_secret(...)`, `execute_with_secret(...)`, `rotate(...)`, `revoke(...)` | Stores encrypted secret versions and allows policy-bound secret use through a callback. |
| Decision Engine | `AgentSecurityOrchestrator.process(...)` | Inspects a typed request and dispatches it to the corresponding configured gateway. |

### Core call signatures

| Service | Constructor / call | Main arguments |
| --- | --- | --- |
| PromptGuard | `PromptAnalyser(llm=None, max_prompt_chars=32_000)`; `.inspect(prompt)`, `.analyse(prompt)`, `.decision(prompt)` | `llm` must implement `.invoke(...)` and return PromptGuard JSON for model-backed analysis; `prompt` is untrusted text/data. |
| MemoryGuard | `GuardedMemoryAccessLayer(registry, cyber_ai=None, audit_log=None, quarantine_store=None)`; `.execute(request, context)` | `registry` binds logical stores to adapters; `request` is a `MemoryRequest`; `context` is a host-created `SecurityContext`. |
| ToolGuard | `ToolGuard(registry=None, audit=None, llm_analyser=None, *, trusted_context=None)`; `.execute(request, context=None)` | Register a `ToolDefinition` and callable; pass a `ToolRequest` plus trusted `ToolSecurityContext`; encrypted audit requires `TOOL_GUARD_KEY` or an explicit key. |
| SecretGuard | `SecretBroker(repository, vault, permissions=None, guard=None)`; `.register_secret(...)`, `.execute_with_secret(...)`, `.rotate(...)`, `.revoke(...)` | `repository` and `vault` are required; requests and contexts are host-created; secret bytes enter only through `SecretMaterial` or a bounded callback. |
| Decision Engine | `AgentSecurityOrchestrator(...).process(request, context=None, *, secret_callback=None, secret_material=None)` | Requires the configured prompt analyser and relevant gateway; request type selects MemoryGuard, ToolGuard, or SecretBroker. |

For detailed constructor arguments, request fields, policies, and runnable examples for each service, see the [ASO Tutorial](aso_tutorial.md) and [Developer Integration Guide](developer_integration.md). Use a guard-created framework tool wrapper; never pass a raw protected callable to the agent.

## Main library entry points

### `AgentSecurityOrchestrator.process(...)`

This is the primary unified entry point for the ASO runtime. It accepts a typed request and dispatches it to the appropriate guard based on the request type.

Supported request types:

- `MemoryRequest`
- `ToolRequest`
- `SecretAccessRequest`

The orchestrator validates prompt content and trusted host context before dispatching. If the request is suspicious, it returns a deny or quarantine result instead of continuing execution.

### Creating the framework agent

`AgentSecurityOrchestrator` creates its initial framework agent during initialization and exposes it as `orchestrator.agent`. Set `agent_name`, `developer_name`, and `agent_description` to provide its metadata; if omitted, ASO generates a name and uses default metadata. The required `llm` argument supplies the model identifier used to create the framework agent.

`create_agent(agent_name, model_name, developer_name, description, tools=None)` creates an additional framework-specific agent and records its metadata. `tools` must contain callables returned by the configured `ToolGuard.create_framework_tool(...)` or `orchestrator.create_framework_tool(...)`; raw callables are rejected.

Orchestrator constructor arguments:

| Argument | Meaning |
| --- | --- |
| `framework` | Framework enum/name such as `Framework.LANGCHAIN`; selects the agent integration. |
| `llm` | Model identifier used for the initial agent; required with `prompt_template`. |
| `prompt_template` | Base instruction combined with the agent description. |
| `M_Definition` | Legacy memory-context fallback; pass a trusted `SecurityContext` or `None`. |
| `T_Definition` | Legacy slot, not the tool registry; pass `None` and configure `tool_guard`/`tool_context`. |
| `S_Definition` | Legacy slot, not the secret broker; pass `None` and configure `secret_broker`/`secret_context`. |
| `database_path` | SQLite path for non-secret orchestrator metadata. |
| `prompt_analyser` | Object with `analyse(text)` returning the PromptGuard decision contract. |
| `memory_access_layer` | Configured `GuardedMemoryAccessLayer`; required for memory requests. |
| `tool_guard`, `tool_context` | Configured ToolGuard and host-created trusted tool identity. |
| `secret_broker`, `secret_context` | Configured SecretBroker and host-created trusted secret identity. |
| `tools` | Optional guarded framework tools for the initially created agent. |

`process(request, context=None, *, secret_callback=None, secret_material=None)` accepts a typed `MemoryRequest`, `ToolRequest`, or `SecretAccessRequest`. `context` is host-created identity for that request. `secret_callback` is required for secret reads; `secret_material` is required for secret writes/updates. It returns `OrchestrationResult(request_id, component, decision, data, reason_codes)`.

```python
# `orchestrator` is configured with the relevant gateway and a tested PromptAnalyser.
result = orchestrator.process(memory_request, context=memory_context)
if result.decision != "ALLOW":
    raise PermissionError(f"ASO blocked this request: {result.reason_codes}")
```

### `GuardedMemoryAccessLayer.execute(...)`

This is the memory-specific gateway. It ensures:

- the store is known and enabled
- the agent identity matches the trusted context
- the requested memory scope is permitted
- the operation is allowed by both the context and the store configuration
- post-read inspection checks retrieved memory

### `ToolGuard.execute(...)`

This gate protects external tool execution. It verifies:

- the tool is registered
- the request is from a trusted agent/session/tool context
- the operation is declared in the tool definition
- the tool usage is in scope
- the tool result itself is safe before returning it to the agent

### `SecretBroker`

This is the secret/credential gateway. It enforces:

- tenant and agent identity matching
- allowed secret type and destination checks
- purpose-based access policy
- read-only or bounded secret callbacks
- encrypted storage and metadata-only request handling

## Trust boundaries matter

ASO deliberately requires trusted host-created context. This is not a library that trusts the agent to say, "I am authorized". Instead, the application creates and provides the authenticated security context.

Examples of host-controlled values:

- agent ID
- tenant ID
- session ID
- authorized tools
- allowed memory stores
- secret policy metadata

Agent-controlled text is never treated as authorization.

## Guard behavior

ASO uses a fail-closed style of enforcement:

- if prompt inspection fails, the request is blocked
- if the trusted context is missing or mismatched, execution is denied
- if the tool result is suspicious, it is quarantined
- if a secret operation breaks policy, it is denied

A quarantine result means the app should notify a human operator or incident system, because the request or output was not accepted for normal execution.

## Example: prompt inspection

```python
from aso import LangChainPromptAnalyser

# Install aso-security[openai] and set OPENAI_API_KEY in the host environment.
analyser = LangChainPromptAnalyser.from_environment(
    provider="openai",
    model_name="gpt-4o-mini",
    max_prompt_chars=32_000,
)
prompt = "Summarize this support ticket."

features = analyser.inspect(prompt)  # Feature extraction only; does not decide authorization.
analysis = analyser.analyse(prompt)
if analysis.decision.decision.value != "ALLOW":
    raise PermissionError(f"PromptGuard blocked this prompt: {analysis.decision.reason_codes}")
```

## Example: memory protection

```python
import os

from aso import (
    GuardedMemoryAccessLayer,
    MemoryRequest,
    Operation,
    SQLITE,
    SecurityContext,
    StoreConfig,
    StoreRegistry,
)

registry = StoreRegistry()
registry.register(StoreConfig(
    store_id="agent-profile",
    store_type="relational",
    provider="sqlite",
    adapter=SQLITE(
        database_path="agent-memory.db",
        encryption_key=os.environ["MEMORY_GUARD_KEY"],
    ),
    memory_types=frozenset({"profile"}),
    capabilities=frozenset({"read", "write", "update", "delete"}),
))
memory = GuardedMemoryAccessLayer(registry)

context = SecurityContext(
    agent_id="agent-42",
    tenant_id="tenant-7",
    session_id="session-1",
    allowed_stores=frozenset({"agent-profile"}),
    permissions=frozenset({"read", "write"}),
)

request = MemoryRequest(
    agent_id="agent-42",
    operation=Operation.WRITE,
    store_id="agent-profile",
    payload={"preference": "be concise"},
    memory_type="profile",
    metadata={"memory_id": "answer-style"},
)

result = memory.execute(request, context)
if result.decision.value != "ALLOW":
    raise PermissionError(f"MemoryGuard blocked this operation: {result.reason_codes}")
```

## Example: tool protection

```python
import os
import uuid

from aso import ToolAuditStore, ToolDefinition, ToolGuard, ToolRegistry, ToolRequest, ToolSecurityContext

registry = ToolRegistry()


def get_status(ticket_id: str) -> dict:
    return {"ticket_id": ticket_id, "status": "open"}

registry.register(
    ToolDefinition(
        tool_id="get_status",
        name="Status lookup",
        description="Fetch ticket status",
        purpose="Check the user's requested ticket status.",
        input_schema={
            "type": "object",
            "properties": {
                "ticket_id": {"type": "string"},
                "operation": {"type": "string"},
            },
            "required": ["ticket_id", "operation"],
        },
        operations=frozenset({"lookup"}),
        allowed_resources=frozenset({"T-100"}),
        output_schema={"type": "object"},
    ),
    get_status,
)

context = ToolSecurityContext(
    agent_id="agent-42",
    session_id="session-1",
    authorized_tools=frozenset({"get_status"}),
)

request = ToolRequest(
    request_id="tool-1",
    agent_id="agent-42",
    session_id="session-1",
    task_id="task-1",
    tool_id="get_status",
    purpose="Check the status of the user's ticket.",
    reason="This is required to answer the user request.",
    arguments={"operation": "lookup", "ticket_id": "T-100"},
)

audit = ToolAuditStore(encryption_key=os.environ["TOOL_GUARD_KEY"])
guard = ToolGuard(registry=registry, audit=audit, trusted_context=context)
result = guard.execute(request, context)
if result.decision.value != "ALLOW_RESULT":
    raise PermissionError(f"ToolGuard blocked this call: {result.reasons}")
print(result.data)

# To expose it to an agent, attach only this wrapper, never get_status itself.
guarded_get_status = guard.create_framework_tool("get_status", context, operation="lookup")
```

## Example: secret protection

```python
import os
import uuid

from aso import (
    LocalDevelopmentKeyManager,
    SecretAccessRequest,
    SecretBroker,
    SecretDefinition,
    SecretMaterial,
    SecretPermissions,
    SecretRepository,
    SecretSecurityContext,
    SecretType,
    SecretVault,
)


repository = SecretRepository("secret-guard.db")
# Development only; set SECRETGUARD_DEV_KEK_B64 outside source code.
vault = SecretVault(repository, LocalDevelopmentKeyManager())
broker = SecretBroker(repository, vault)

permissions = SecretPermissions(
    allowed_use=True,
    allowed_type=frozenset({SecretType.OPENAI_API_KEY}),
    allowed_destination=frozenset({"vault", "openai-api"}),
    allowed_operations=frozenset({"store", "read"}),
    allowed_exposed=True,
)
secret_id, _ = broker.register_secret(
    SecretDefinition(
        name="support-agent credential",
        secret_type=SecretType.OPENAI_API_KEY,
        source="host secret manager",
        operations=frozenset({"store", "read"}),
        destinations=frozenset({"openai-api"}),
        allowed=True,
        exposed=True,
    ),
    SecretMaterial.from_value(os.environ["OPENAI_API_KEY"]),
    tenant_id="tenant-7",
    permissions=permissions,
)

context = SecretSecurityContext(
    tenant_id="tenant-7",
    requester="service-account",
    agent_id="agent-42",
    session_id="session-2",
    authorized_tools=frozenset({"get_status"}),
)

request = SecretAccessRequest(
    request_id=str(uuid.uuid4()),
    secret_id=secret_id,
    tenant_id="tenant-7",
    requester="service-account",
    agent_id="agent-42",
    session_id="session-2",
    tool_id="get_status",
    purpose="Run the API call needed for the current user request.",
    operation="read",
    destination="openai-api",
)

def call_provider(secret_view):
    token = secret_view.tobytes().decode("utf-8")
    return provider_client.call(api_key=token)  # Return provider data, never the token.


result = broker.execute_with_secret(
    request,
    context,
    call_provider,
)
print("provider result received")
```

## Production guidance

For production deployment, ASO should be used with:

- authenticated host-side identity
- KMS-backed secret management
- explicit tool registry policies
- explicit tenant/session scoping
- activity logs and audit review
- alerting for quarantined events
- tested security policy defaults

## License

ASO is licensed under the Apache License 2.0.

## Links

- GitHub: https://github.com/AyoubStudent/ASO
- Repository: https://github.com/AyoubStudent/ASO
- PyPI: https://pypi.org/project/aso-security/
