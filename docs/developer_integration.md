# ASO Developer Integration Guide

ASO is a security layer around an AI agent not an agent framework. It does not automatically intercept model tool calls or database connections. Your application must route every protected operation through the matching ASO guard and must not give the agent another path to that resource.

## Choose an integration path

| Path | Use it when | Your application does |
| --- | --- | --- |
| `AgentSecurityOrchestrator.process(...)` | You want one API to inspect a typed request and dispatch it to memory, tool or secret protection. | Build a typed request, provide a host-created trusted context and configure the required gateways and prompt analyser. |
| Direct service APIs | You want to integrate one guard into an existing application flow. | Call `PromptAnalyser`, `GuardedMemoryAccessLayer`, `ToolGuard`, or `SecretBroker` at the resource boundary. |

Both paths require host-side identity and policy. Prompt inspection detects suspicious content; it is not authorization. Resource-specific guards are still required.

## What ASO provides

| Service | Responsibility | Main API |
| --- | --- | --- |
| PromptGuard | Inspects prompt/request text and returns a decision plus features and reasons. | `PromptAnalyser.analyse(prompt)` |
| Decision Engine | Provides the unified `process(...)` entry point, checks prompt-analysis results, validates trusted context, and dispatches typed resource requests. | `AgentSecurityOrchestrator.process(request, context=...)` |
| MemoryGuard | Checks identity, store scope, operation permissions, and memory policy before calling a registered adapter; inspects returned data. | `GuardedMemoryAccessLayer.execute(request, context)` |
| ToolGuard | Resolves a developer-defined tool, checks the request, runs its registered callable, inspects the result, and records an audit event. | `ToolGuard.execute(request, context)` |
| SecretGuard | Applies secret policy and brokers encrypted storage, bounded secret use, rotation, revocation, and audit. | `SecretBroker` methods |
| Audit and quarantine | Returns decisions/reason codes and records guard events; the application connects alerts and incident workflows. | Guard result objects and host-owned alert handlers |

## Install

From the published package:

```bash
python -m pip install aso-security
```

The base package includes its database and prompt-inspection runtime dependencies, including Pydantic and SQLAlchemy. Install only the model integration your application uses:

```bash
python -m pip install "aso-security[openai]"
python -m pip install "aso-security[google]"
python -m pip install "aso-security[huggingface]"
python -m pip install "aso-security[ollama]"
python -m pip install "aso-security[langchain]"
```

To install all listed model integrations together:

```bash
python -m pip install "aso-security[all]"
```

From a source checkout:

```bash
python -m pip install -e .
```

Memory-provider SDKs are optional; install only the adapters you configure. Examples:

```bash
python -m pip install "aso-security[memory-qdrant]"
python -m pip install "aso-security[memory-postgresql]"
python -m pip install "aso-security[memory-mongodb]"
python -m pip install "aso-security[memory-all]"
```

Available extras include `memory-qdrant`, `memory-pinecone`, `memory-weaviate`, `memory-milvus`, `memory-chroma`, `memory-faiss`, `memory-sql`, `memory-postgresql`, `memory-pgvector`, `memory-oracle`, `memory-sqlserver`, `memory-mariadb`, `memory-mongodb`, `memory-couchdb`, `memory-firestore`, `memory-dynamodb`, `memory-redis`, `memory-valkey`, `memory-memcached`, `memory-neo4j`, `memory-neptune`, `memory-arango`, `memory-tigergraph`, `memory-langgraph`, `memory-elasticsearch`, `memory-opensearch`, `memory-solr`, `memory-s3`, `memory-gcs`, `memory-azure`, and `memory-yaml`.

An extra installs a Python SDK, not the database service, native drivers, credentials, or provider schema. Provider APIs, SDK versions, and schema requirements still need validation in your deployment. `memory-faiss` excludes Windows because upstream FAISS wheels are not generally available there.

### Existing data migration

Backend record IDs are now derived from the trusted tenant ID, agent ID, and logical memory ID. This prevents two principals with the same logical memory ID from overwriting or reading one another's records. Data written by earlier ASO versions under raw, unscoped IDs is not automatically visible through the new CRUD paths. Back up provider data and perform a provider-specific migration that assigns each legacy row to its authoritative tenant before upgrading; do not infer tenant ownership from agent-controlled request data.

## Orchestrator definition parameters

`M_Definition`, `T_Definition`, and `S_Definition` are legacy required positional parameters. They do not all take the same kind of object and should not be used as the current resource registries:

| Parameter | Current meaning | Recommended value |
| --- | --- | --- |
| `M_Definition` | Default trusted memory context used when a memory `process(...)` call omits `context`. | A host-created `SecurityContext`, or `None` if every request passes an explicit context. |
| `T_Definition` | Stored for compatibility; it is not the active tool registry or authorization policy. | `None`. Configure `tool_guard` and `tool_context` instead. |
| `S_Definition` | Stored for compatibility; it is not the active secret registry or authorization policy. | `None`. Configure `secret_broker` and `secret_context` instead. |

Example with a host-created default memory context and explicit tool/secret gateways:

```python
orchestrator = AgentSecurityOrchestrator(
    framework=Framework.LANGCHAIN,
    llm="your-agent-model",
    prompt_template="Use only guarded resources.",
    M_Definition=memory_context,
    T_Definition=None,
    S_Definition=None,
    prompt_analyser=prompt_analyser,
    memory_access_layer=memory_gateway,
    tool_guard=tool_guard,
    tool_context=tool_context,
    secret_broker=secret_broker,
    secret_context=secret_context,
)
```

For stronger per-call identity binding, pass `context=...` on each `process(...)` call rather than relying on a configured default.

## Protect an agent tool

The key integration rule is to register the real implementation inside `ToolRegistry`, then expose only an application wrapper that calls `ToolGuard`. Do not register the raw function directly with the agent framework.

```python
import os

from aso import (
    ToolDefinition,
    ToolAuditStore,
    ToolGuard,
    ToolRegistry,
    ToolSecurityContext,
)


def lookup_ticket(ticket_id: str, operation: str) -> dict:
    # Call your real ticket service here.
    return {"ticket_id": ticket_id, "status": "open"}


registry = ToolRegistry()
registry.register(
    ToolDefinition(
        tool_id="ticket_lookup",
        name="Ticket lookup",
        description="Read the status of an approved ticket.",
        purpose="Look up a ticket requested by the authenticated user.",
        input_schema={
            "type": "object",
            "properties": {
                "ticket_id": {"type": "string"},
                "operation": {"type": "string"},
            },
            "required": ["ticket_id", "operation"],
        },
        operations=frozenset({"read"}),
        allowed_resources=frozenset({"T-100"}),
        output_schema={"type": "object"},
    ),
    lookup_ticket,
)

# Create this only from authenticated application state, never from model output.
context = ToolSecurityContext(
    agent_id="agent-42",
    session_id="session-7",
    authorized_tools=frozenset({"ticket_lookup"}),
)

audit = ToolAuditStore(encryption_key=os.environ["TOOL_GUARD_KEY"])
guard = ToolGuard(registry=registry, audit=audit)
guarded_ticket_lookup = guard.create_framework_tool("ticket_lookup", context)


# In your agent framework, expose guarded_ticket_lookup, never lookup_ticket.
```

`TOOL_GUARD_KEY` must be a Fernet-compatible URL-safe base64 key and must stay stable while the audit database exists; changing it makes older encrypted audit fields unreadable. Generate a key once with `Fernet.generate_key()`, store it in your deployment secret manager, then inject it through the environment. Do not generate a new key on every application start or commit the key to source control.

One-time provisioning code (run in a secure setup context and store the result directly in your secret manager; do not print it):

```python
from cryptography.fernet import Fernet

tool_guard_key = Fernet.generate_key().decode("ascii")
secret_manager.store("TOOL_GUARD_KEY", tool_guard_key)
```

`create_framework_tool` supplies the trusted identity, fixed purpose/reason, task and request ID, and routes the call through `ToolGuard.execute`. Treat the model's declared arguments as untrusted. Keep a second authorization check inside the underlying service for high-impact operations; ASO does not replace provider-side permissions.

## Create an ASO-managed framework agent

The `tools` argument is accepted only for framework callables created by the configured `ToolGuard`. Raw functions and wrappers from another guard are rejected. For the direct path, pass the wrapper from `guard.create_framework_tool(...)` to `tools=`. For the orchestrated path, create the orchestrator first, then use its `create_framework_tool(...)` factory, which routes each call through `process(...)`:

```python
from aso import AgentSecurityOrchestrator, Framework


# Use a PromptAnalyser configured with a model that follows ASO's decision JSON contract.
prompt_analyser = configured_prompt_analyser

orchestrator = AgentSecurityOrchestrator(
    framework=Framework.LANGCHAIN,
    llm="your-agent-model",
    prompt_template="Use only the supplied guarded tools.",
    M_Definition=None,
    T_Definition=None,
    S_Definition=None,
    prompt_analyser=prompt_analyser,
    tool_guard=guard,
    tool_context=context,
    database_path="aso.db",
)
orchestrated_ticket_lookup = orchestrator.create_framework_tool("ticket_lookup", context)
agent = orchestrator.create_agent(
    agent_name="support-agent",
    model_name="your-agent-model",
    developer_name="Example Engineering",
    description="Handles support requests using guarded services.",
    tools=[orchestrated_ticket_lookup],
)
```

For the direct path, pass `tools=[guarded_ticket_lookup]` to the constructor or `create_agent(...)`; that wrapper calls `guard.execute(...)`. In both paths, the implementation must be registered with `ToolRegistry`, and only the guard-created wrapper is given to the framework.

The constructor also creates `orchestrator.agent`. If you need a separately named agent, call the class method explicitly and pass only guarded framework tools:

```python
another_agent = orchestrator.create_agent(
    agent_name="billing-agent",
    model_name="your-agent-model",
    developer_name="Example Engineering",
    description="Handles billing questions using guarded services.",
    tools=[orchestrated_ticket_lookup],
)
```

This creates an additional framework agent; it does not change `orchestrator.agent` or install automatic interception hooks.

Configure `TOOL_GUARD_KEY` (or inject an explicit audit key) before creating `ToolAuditStore`; there is no built-in fallback key. Keep the key outside source control and agent-visible configuration in every environment.

## Connect an existing agent

The integration point is the agent framework's tool/function dispatcher:

1. The model proposes a function call.
2. The host validates the requested tool against its own registered tool list.
3. The host builds a `ToolRequest` using authenticated IDs and fixed policy text; it does not trust identity fields returned by the model.
4. The host calls `ToolGuard.execute(...)`, or sends the request to `AgentSecurityOrchestrator.process(...)`.
5. The host returns `result.data` to the agent only for an allowed result. Denials and quarantines should stop that operation and may trigger host-side alerting.

Never give the model a database client, secret vault, raw tool callable, or credentials that let it bypass this dispatcher.

## Use the unified orchestrator

`process(...)` accepts `MemoryRequest`, `ToolRequest`, and `SecretAccessRequest`. Configure the relevant gateway and pass a trusted context per request (or configure a trusted default on the orchestrator). The orchestrator analyzes the serialized request first; anything other than `ALLOW` stops before resource dispatch.

```python
result = orchestrator.process(tool_request, context=trusted_tool_context)

if result.decision == "ALLOW_RESULT":
    deliver_to_agent(result.data)
elif result.decision in {"DENY", "REVIEW", "QUARANTINE"}:
    stop_tool_call()
    notify_security_team(result.reason_codes)
```

The orchestrator does not automatically install hooks into LangChain, CrewAI, ADK, AutoGen, or another framework. You still connect the framework's call dispatcher to the guarded wrapper. Only pass framework tools that are already guarded.

The same rule applies to memory and secrets. `process(...)` protects a memory operation only when the host turns it into a `MemoryRequest` and calls `process`; framework-managed memory is not intercepted automatically. Secret operations likewise run only when the host submits a `SecretAccessRequest` through `process(...)`, or invokes the configured `SecretBroker` directly in a guarded host wrapper. Merely configuring a `SecretBroker`, or running an agent that uses tools and memory, does not automatically cause SecretGuard checks.

| Resource | Direct route | Orchestrated route |
| --- | --- | --- |
| Tool | `guard.create_framework_tool(...)` returns a callable that uses `ToolGuard.execute`. | `orchestrator.create_framework_tool(...)` returns a callable that uses `process(...)`. |
| Memory | Host calls `GuardedMemoryAccessLayer.execute(request, context)`. | Host creates a `MemoryRequest` and calls `process(memory_request, context)`. |
| Secret | Trusted host code calls `SecretBroker` with a `SecretAccessRequest` and context. | Host calls `process(secret_request, context, secret_callback=...)` for reads, or passes `secret_material` for writes/updates. |

Secret registration is always trusted host setup through `SecretBroker.register_secret(...)`; `process(...)` does not register new secrets from agent requests.

Prompt analysis must be explicitly configured and tested for the model/provider you deploy. A model response must conform to PromptGuard's decision JSON contract. If analysis fails or does not return `ALLOW`, the orchestrator fails closed. Do not treat a generic language model or a heuristic prompt scan as a complete authorization policy.

## Other services

### Memory

Register each host-created adapter in `StoreRegistry` with a `StoreConfig`. Create the `SecurityContext` from authenticated server-side identity and route every operation through `GuardedMemoryAccessLayer.execute(...)`:

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


stores = StoreRegistry()
stores.register(StoreConfig(
    store_id="profile",
    store_type="relational",
    provider="sqlite",
    adapter=SQLITE(
        database_path="agent-memory.db",
        encryption_key=os.environ["MEMORY_GUARD_KEY"],
    ),
    memory_types=frozenset({"profile"}),
    capabilities=frozenset({"read", "write", "update", "delete", "search"}),
))
memory = GuardedMemoryAccessLayer(stores)

# Build from authenticated host state; never accept these values from model output.
context = SecurityContext(
    agent_id="agent-42",
    tenant_id="tenant-7",
    session_id="session-7",
    allowed_stores=frozenset({"profile"}),
    permissions=frozenset({"read", "write"}),
)
request = MemoryRequest(
    agent_id=context.agent_id,
    operation=Operation.WRITE,
    store_id="profile",
    payload={"preferred_language": "French"},
    memory_type="profile",
    metadata={"memory_id": "language-preference"},
)

result = memory.execute(request, context)
if result.decision.value != "ALLOW":
    raise PermissionError(f"MemoryGuard blocked the operation: {result.reason_codes}")
```

`MEMORY_GUARD_KEY` must be a Fernet-compatible key held by the application, not the agent. Generate and store it using the same one-time secret-manager pattern as `TOOL_GUARD_KEY`; keep it stable for existing data. The host chooses the adapter, configures its credentials, and controls each store's `memory_types` and `capabilities`. A search request is still a guarded request; provider similarity-search behavior depends on the selected adapter implementation.

### Secrets

Create a `SecretRepository`, a `SecretVault`, and a `SecretBroker`. Register secrets in trusted host setup; requests contain a secret ID, never the secret value. For a direct read, the broker passes temporary material to one narrow callback and audits the result:

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
# Set SECRETGUARD_DEV_KEK_B64 from a local secret store before running this example.
# Development only. In production inject a KMS/HSM-backed KeyManager.
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
        name="support-agent OpenAI credential",
        secret_type=SecretType.OPENAI_API_KEY,
        source="application secret manager",
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
    requester="support-service",
    agent_id="agent-42",
    session_id="session-7",
    authorized_tools=frozenset({"chat_completion"}),
)
request = SecretAccessRequest(
    request_id=str(uuid.uuid4()),
    secret_id=secret_id,
    tenant_id="tenant-7",
    requester="support-service",
    agent_id="agent-42",
    session_id="session-7",
    tool_id="chat_completion",
    purpose="Authenticate the approved support-service API request.",
    operation="read",
    destination="openai-api",
)

def call_provider(secret_view):
    token = secret_view.tobytes().decode("utf-8")
    return provider_client.call(api_key=token)  # Return business data, never the token.

safe_result = broker.execute_with_secret(request, context, call_provider)
```

`allowed_exposed=True` and `definition.exposed=True` are required for plaintext to reach the callback. Enable them only for a narrowly scoped use like this; never return, log, or persist the secret itself. The sample `LocalDevelopmentKeyManager` requires `SECRETGUARD_DEV_KEK_B64` and is strictly for development. Production must inject a KMS/HSM-backed key manager.

### Prompt inspection

Use `PromptAnalyser.analyse(...)` when you need a prompt-level decision without resource dispatch. `PromptAnalysis` contains the normalized prompt, extracted features, and a `GuardDecision`. Apply the decision explicitly in the host application; calling the analyser alone does not guard tools, memory, or secrets.

Inject a model whose `.invoke(...)` method returns the required JSON decision. Call `inspect(...)` for features only, or `analyse(...)` when you also want the model decision:

```python
from aso import PromptAnalyser


# `security_model` is a host-configured model adapter tested to return ASO decision JSON.
prompt_analyser = PromptAnalyser(llm=security_model)
prompt = "Please summarize this support ticket."

features = prompt_analyser.inspect(prompt)
strength = features["instruction_features"]["instruction_strength"]
analysis = prompt_analyser.analyse(prompt)

print("instruction strength:", strength["level"], strength["signals"])
if analysis.decision.decision.value != "ALLOW":
    raise PermissionError(f"PromptGuard blocked the prompt: {analysis.decision.reason_codes}")
```

`inspect(...)` does not call the model or authorize anything. `analyse(...)` fails closed as `QUARANTINE` when the model is missing, fails, or does not return the expected JSON. The multilingual strength score is a heuristic signal; it is not a substitute for resource-specific authorization.

PromptGuard also reports multilingual instruction-strength and override phrase signals for English, Spanish, French, German, Portuguese, Italian, Russian, Arabic, Chinese, Japanese, Korean, and Hindi. These are curated lexical heuristics, not language understanding: paraphrases, transliteration, dialects, and other languages may be missed. Treat the feature as supporting evidence only; it does not independently authorize or deny a request.

### Alerts and audit

ASO returns decisions and reason codes and records guard audit events. Email, Slack, SIEM, paging, retention, and incident-response policy belong to the application. Trigger those systems from structured guard results, and avoid sending prompts, secret values, or raw sensitive tool outputs to alert channels.

## Integration checklist

- Create trusted contexts from authenticated server-side state.
- Register only the tools and stores each agent needs.
- Ensure the framework exposes guarded wrappers, not raw implementations.
- Keep an alternate direct path to protected resources unavailable to the agent.
- Check the result decision before returning tool output to the model or user.
- Configure production audit encryption and a production secret key manager.
- Test allowed, denied, malformed, out-of-scope, and failed-analysis requests.
