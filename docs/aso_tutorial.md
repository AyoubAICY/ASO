# ASO Tutorial

This tutorial describes the current ASO API and shows how to put its guards between an agent and protected resources. ASO is a security-boundary library not an agent framework:
 the application remains responsible for authenticating identities, selecting policies, configuring provider models and keeping guard gateways on every path to a resource.

## Install

Install the published distribution and only the integrations you use:

```bash
python -m pip install "aso-security"
python -m pip install "aso-security[google]"
```

For a checkout, install development dependencies with `python -m pip install -e ".[dev]"`.

## Security Flow

1. The host authenticates the caller and constructs trusted identity context. Never build this context from agent-controlled text.
2. The host sends a typed request to `AgentSecurityOrchestrator.process`.
3. The configured `PromptAnalyser` inspects the request. Anything other than `ALLOW`, or an analysis failure, stops dispatch.
4. The matching resource gateway independently checks permissions and policy.
5. Only an authorized gateway invokes its adapter, registered tool, or secret callback.
6. The caller handles the typed result and reason codes without exposing credentials or audit data.

Prompt inspection is not authorization. Keep the resource-specific guard in front of the actual adapter or function, including when an agent framework has its own tool registry.

## Four Developer Entry Points

ASO exposes four main ways to run the security applications:

| Entry point | What it runs | Caller supplies |
| --- | --- | --- |
| `GuardedMemoryAccessLayer.execute(request, context)` | MemoryGuard authorization, adapter operation, retrieved-data inspection, audit/quarantine handling. | A registered store, a `MemoryRequest`, and a host-created `SecurityContext`. |
| `ToolGuard.execute(request, context=None)` | Tool pre-check, registered callable execution, result post-check, and audit. | A `ToolRequest`, registered definition/callable, and host-created trusted context. |
| `SecretBroker` methods | Secret registration, policy-gated use/rotation/revocation, encryption, and audit. | Repository, vault/key manager, typed request, host-created context, and operation callback/material. |
| `AgentSecurityOrchestrator.process(...)` | Prompt analysis followed by dispatch to one of the three gateways above. | A typed request, configured gateways, and trusted context (explicit or configured default). |

The first three are direct service entry points. They do not create an agent or infer trustworthy identity from user text. `process` is the unified interface when the application wants ASO to select the gateway by request type. `create_agent(...)` creates an agent but does not attach unguarded tools.

memory invokes the registered adapter, tools invoke the registered callable, and secret use invokes the supplied callback with temporary material. Developers still configure the resource connection, tool implementation, permissions, identity context and (for secrets) a key manager. ASO cannot safely infer those from an agent request.

## AgentSecurityOrchestrator

```python
AgentSecurityOrchestrator(
    framework, llm, prompt_template, M_Definition, T_Definition, S_Definition,
    database_path="aso.db", *, prompt_analyser=None, memory_access_layer=None,
    tool_guard=None, secret_broker=None, secret_context=None, tool_context=None, tools=None,
)
```

| Argument | Meaning |
| --- | --- |
| `framework` | Converted to `Framework`. Values: `LANGCHAIN`, `CREWAI`, `AUTOGEN_MICROSOFT`, `GOOGLE_AGENT`, `OPENAI_SDK`, `LLAMAINDEX`, `PYDANTIC_AI`. The corresponding integration package is needed when calling `create_agent`. |
| `llm` | Required non-empty identifier retained on the orchestrator. It is not a model client; `create_agent` gets its model via `model_name`. |
| `prompt_template` | Required base instruction; combined with agent description by `create_agent`. |
| `M_Definition` | Legacy memory-context fallback. Must be a trusted `SecurityContext` if memory `process` is called without explicit context. |
| `T_Definition` | Legacy compatibility argument. Current tool dispatch uses `tool_guard` and `ToolSecurityContext`. |
| `S_Definition` | Legacy compatibility argument. Current secret dispatch uses `secret_broker` and `SecretSecurityContext`. |
| `database_path` | SQLite file for agent and decision metadata; `":memory:"` is useful in tests. Never store secret material here. |
| `prompt_analyser` | Object implementing `analyse(text)`. Configure and inject a tested analyser for deployment; the default setup may lack an available or compatible model and then fails closed. |
| `memory_access_layer` | Memory gateway. Requests are denied when it is absent. |
| `tool_guard` | `ToolGuard` instance. Requests are denied when absent. |
| `secret_broker` | `SecretBroker` instance. Requests are denied when absent. |
| `secret_context` | Host-created default `SecretSecurityContext` for secret requests. |
| `tool_context` | Host-created default `ToolSecurityContext` for tool requests. |
| `tools` | Explicit framework tool list attached to the initially created agent. Every item must be returned by the configured `ToolGuard` or orchestrator `create_framework_tool(...)` factory; raw callables are rejected. |
| `agent_name` | Optional name for the automatically created initial agent. |
| `developer_name` | Optional developer/organization metadata stored for the agent. |
| `agent_description` | Optional description supplied to the initial framework agent. |

The three positional definition arguments are currently required even when unused; pass `None` for unused legacy slots. The actual gateways are the keyword arguments above.

`process(request, context=None, *, secret_callback=None, secret_material=None)` accepts `MemoryRequest`, `ToolRequest`, or `SecretAccessRequest`. `context` is authenticated per-request context; if omitted, the configured default is used. Secret reads require an application-owned callback. Secret writes/updates require `SecretMaterial`, cleared on denied/error paths. The result is `OrchestrationResult(request_id, component, decision, data, reason_codes)`.

| `process` argument | Required content and behavior |
| --- | --- |
| `request` | One of the three typed request objects below. It must have a non-empty `request_id`; the request itself is first serialized and sent through prompt analysis. |
| `context` | Host-authenticated context matching the request: `SecurityContext` for memory, `ToolSecurityContext` for tools, or `SecretSecurityContext` for secrets. `None` selects the configured fallback. A mismatch denies dispatch. |
| `secret_callback` | Callable accepting one temporary `memoryview`. Used only for secret `read`; design it to perform the necessary operation and return a minimal derived result, never the plaintext bytes. |
| `secret_material` | `SecretMaterial` for secret `write`/`update` (the broker rotates the stored value). It is cleared on guarded failure paths. Do not reuse it after passing it in. |

For memory and tool requests, `process` calls the configured gateway with the request and trusted context. For secrets, it calls `secret_broker.execute_with_secret`, `rotate`, or `revoke`, depending on `request.operation`. Current `process` supports secret operations `read`, `write`, `update`, and `delete`; direct broker registration is a separate setup call. Prompt analysis must return `ALLOW` before any of those calls happen.

`guard.create_framework_tool(tool_id, context, operation=None)` creates a framework-callable that dispatches through `ToolGuard.execute(...)`. `orchestrator.create_framework_tool(...)` creates one that dispatches through `process(...)`, including prompt inspection. Pass only these guard-created wrappers to `AgentSecurityOrchestrator(..., tools=...)` or `create_agent(..., tools=...)`; raw or foreign callables are rejected. Close the SQLite connection with `close()` or a `with` block.

Neither agent creation nor `process(...)` automatically hooks framework-managed memory or secret access. Memory and secret operations are protected only when the host routes typed requests through `process(...)` or invokes the corresponding gateway directly. Secret registration remains trusted host setup through `SecretBroker.register_secret(...)`.

### Decision classification helper

`LLM_Query(q, client=None, model=None, provider=None)` classifies a non-empty query and validates a JSON response with `component`, `action`, `reasons`, `suspicious`, and `results`. `client` is an application-configured provider client; `model` and `provider` select its model/provider. This helper classifies intent only. It does not authorize or execute resource operations; use a guard and trusted context for that.

```python
from aso import LLM_Query

classification = LLM_Query(
    "The agent needs to read a ticket and call the support API.",
    client=decision_model_client,
    provider="openai",
    model="gpt-4o-mini",
)
print(classification["component"], classification["action"])
```

## PromptAnalyser

```python
PromptAnalyser(llm=None, max_prompt_chars=32_000)
```

| Argument | Meaning |
| --- | --- |
| `llm` | Object with `invoke(prompt)`. Its response must contain JSON with `decision` (`ALLOW`, `DENY`, or `QUARANTINE`), optional numeric `risk_score`, and optional `reason`. Inject a tested security model for production. |
| `max_prompt_chars` | Positive maximum size. Current code compares UTF-8 byte length with this value. |

`inspect(prompt)` returns extracted features; `analyse(prompt)` returns `PromptAnalysis(prompt, features, decision)`; `decision(prompt)` returns only the `GuardDecision`. Empty or over-limit input raises `ValueError`; inspection/model failures become `QUARANTINE`.

Without an injected model, it attempts to create a Hugging Face text-generation pipeline using `PROMPT_GUARD_LLM_MODEL` or `distilbert-base-uncased`. This pipeline is not guaranteed to implement PromptGuard's decision-JSON contract; if a usable `.invoke(...)` model is unavailable or the response is invalid, analysis returns `QUARANTINE`. `LangChainPromptAnalyser.from_environment(provider, model_name, max_prompt_chars)` supports OpenAI, Google, Hugging Face, and Ollama, requiring matching optional packages and credentials. Verify the selected model's response contract before deployment.

```python
from aso import LangChainPromptAnalyser
from aso import PromptAnalyser

# Select a provider extra first, then configure its credential in the host environment.
analyser = LangChainPromptAnalyser.from_environment(
    provider="openai",
    model_name="gpt-4o-mini",
    max_prompt_chars=32_000,
)
analyser_prompts = PromptAnalyser(
    llm="gpt-4o-mini",
    max_prompt_chars=32_000,
)
prompt = "Summarize this support request."

features = analyser_prompts.inspect(prompt)       # deterministic feature extraction only
analysis = analyser_prompts.analyse(prompt)        # features plus model decision
print(features["instruction_features"]["instruction_strength"])
print(analysis.decision.decision.value, analysis.decision.reason_codes)
```

`inspect` does not authorize or block. `analyse` requires a model that returns PromptGuard's JSON schema and fails closed otherwise. Use the actual `analysis.decision` when deciding whether host code may continue.


## Memory gateway call and payload

The public operation is `GuardedMemoryAccessLayer.execute(request, context) -> AccessResult`. It owns the complete guarded flow for one memory operation. Register each backing adapter once; then pass the typed request and trusted context per call:

```python
GuardedMemoryAccessLayer(
    registry,
    cyber_ai=None,
    audit_log=None,
    quarantine_store=None,
)
```

| Constructor argument | Meaning |
| --- | --- |
| `registry` | Required `StoreRegistry` containing host-configured adapters. |
| `cyber_ai` | Optional `CyberAI` policy extension. By default MemoryGuard uses deterministic feature analysis. |
| `audit_log` | Optional in-process `AuditLog`; otherwise one is created. |
| `quarantine_store` | Optional in-process `QuarantineStore`; otherwise one is created. |

`StoreRegistry.register(StoreConfig(...))` adds a logical store; `resolve(store_id)` is used by the gateway and `list_store_ids()` returns registered IDs. Keep adapters and credentials in host setup; never derive them from request fields.

```python
from aso import (
    GuardedMemoryAccessLayer,
    MemoryRequest,
    Operation,
    SecurityContext,
    SQLITE,
    StoreConfig,
    StoreRegistry,
)
import os


registry = StoreRegistry()
registry.register(StoreConfig(
    store_id="agent-profile",
    store_type="relational",
    provider="sqlite",
    adapter=SQLITE(
        database_path="agent_memory.db",
        encryption_key=os.environ["MEMORY_GUARD_KEY"],
    ),
    memory_types=frozenset({"profile"}),
    capabilities=frozenset({"read", "write", "update", "delete"}),
))
memory = GuardedMemoryAccessLayer(registry)

# Create this context from authenticated application state, never from the agent.
context = SecurityContext(
    agent_id="agent-42",
    tenant_id="tenant-7",
    session_id="session-2026-04",
    allowed_stores=frozenset({"agent-profile"}),
    permissions=frozenset({"read", "write"}),
)
request = MemoryRequest(
    agent_id="agent-42",
    operation=Operation.WRITE,
    store_id="agent-profile",
    payload={"preference": "concise answers"},
    memory_type="profile",
    metadata={"memory_id": "answer-style"},
)
result = memory.execute(request, context)
if result.decision.value == "ALLOW":
    print("memory operation completed", result.operation_id)
else:
    print("memory operation blocked", result.reason_codes)
```
The public `aso` package exports adapter constructors for SQLite, PostgreSQL, Oracle, SQL Server, MariaDB, PGVector, Qdrant, Pinecone, Weaviate, Milvus, Chroma, FAISS, Vespa, MongoDB, CouchDB, Firestore, DynamoDB, Redis, Valkey, Memcached, Neo4j, Neptune, ArangoDB, TigerGraph, LangGraph, Solr, OpenSearch, Elasticsearch, S3, Google Cloud Storage, Azure Blob Storage, and JSON/YAML/CSV/TXT/local-file storage. Import the constructors from `aso`; each remote provider also requires its optional SDK extra, running service, credentials, and compatible schema.

These adapters expose the gateway's ID-based CRUD contract. They are not interchangeable semantic-search implementations: for example, `SEARCH` currently routes to a record lookup by `memory_id`, not vector similarity search. Provider integration tests against real services are still required before production use.

`execute` arguments:

| Argument | Required content |
| --- | --- |
| `request` | `MemoryRequest`. `agent_id` must equal the context identity; `store_id` must be registered and in `allowed_stores`; `operation` must be enabled both in context permissions and store capabilities. |
| `context` | Trusted `SecurityContext`; must contain the authenticated `agent_id`, non-empty `tenant_id` and `session_id`, the allowed store IDs, and permitted operations. Its `policies` mapping is optional metadata; current gateway authorization is primarily based on identity, scopes, and permissions. |

`MemoryRequest` fields:

| Field | What to put in it |
| --- | --- |
| `agent_id` | Authenticated agent identifier; must match `context.agent_id`. |
| `operation` | `read`, `search`, `write`, `update`, or `delete`. `search` is treated as a read for MemoryGuard policy. |
| `store_id` | Logical registered store ID, not a connection string or credential. |
| `request_id` | Correlation ID; generated when omitted. Supply one if you need to correlate logs across services. |
| `payload` | New memory content for `write`/`update`; any structured value is serialized for inspection. |
| `query` | Search/read query text when the adapter supports it. |
| `limit` | Integer 1 through 1000; a bound for adapters that use result limits. |
| `filters` | Structured filter mapping for the adapter. |
| `memory_type` | Policy category such as `profile` or `conversation`; must be in `StoreConfig.memory_types` (or `*`). |
| `metadata` | Non-secret adapter metadata. `metadata["memory_id"]` selects a specific item in the current gateway implementation. Do not put credentials here. |

`StoreConfig` fields are `store_id` (logical key), `store_type` (category label), `provider` (adapter provider label), `adapter` (object exposing operation methods), `memory_types` (allowed categories), `capabilities` (allowed operations), `enabled` (gate switch), and optional non-secret `metadata`. `StoreRegistry.register(config)` makes this store available. `AccessResult` returns request ID, decision, data only when allowed, reason codes, and an optional operation ID.

The lower-level `MemoryGuard(action, source, infos=None, cyber_ai=None).evaluate()` is useful when an application needs a memory-content decision without adapter dispatch. `action` is `read`, `write`, `update`, or `delete`; `source` contains inspected `data` and optional `metadata`; `infos` carries host-supplied policy metadata; `cyber_ai` optionally supplies the analysis extension. It does not replace `GuardedMemoryAccessLayer`, because it does not select or invoke a registered adapter or write the gateway audit event.

`CyberAI(analyzer=None)` can use deterministic analysis or an application callback with signature `(payload_text, feature_mapping)`. The callback returns a decision string or mapping with `decision`, optional `risk_score`, `confidence`, and `reason`; exceptions and malformed responses quarantine. `LangChainCyberAI(model, max_source_chars=32_000, temperature=0.0)` accepts a configured model implementing `.invoke(...)`; its `authorize(payload, features, action="unknown")` analyzes one bounded memory action. Keep model clients tool-free and do not provide adapter credentials to them.

To power MemoryGuard's cyber analysis with a Hugging Face model, install `aso-security[huggingface]` and inject `LangChainCyberAI` into the memory gateway:

```python
from aso import GuardedMemoryAccessLayer, LangChainCyberAI

cyber_ai = LangChainCyberAI.from_environment(
    provider="huggingface",
    model_name="Qwen/Qwen2.5-1.5B-Instruct",
    max_source_chars=32_000,
)
memory = GuardedMemoryAccessLayer(registry, cyber_ai=cyber_ai)
```

Set `MEMORY_GUARD_LLM_MODEL` instead of passing `model_name` to configure the model through the environment. The factory uses a Transformers `text-generation` pipeline and asks the model for JSON containing `decision`, `risk_score`, `confidence`, and `reason`. Choose an instruction-tuned model with enough local compute; if the model fails or returns invalid JSON, CyberAI returns `quarantine`. Validate this behavior with your selected model before deployment. `LangChainCyberAI.from_environment(...)` also accepts `openai`, `google`, and `ollama` providers with their corresponding extras.

## Adapter credentials and secret-backed credentials

ASO separates credential ownership from agent-controlled request data.

For memory adapters, credentials are configured in the application before the adapter is registered in the `StoreRegistry`. The adapter object is responsible for connecting to its provider, and the app owns the environment or secret resolution. `ProviderCredentials` is the application-facing contract for this step:

```python
import os
from MemoryGuard.config import ProviderCredentials, SecurityContext, MemoryRequest, Operation

credentials = ProviderCredentials(
    provider="qdrant",
    endpoint="https://example-qdrant.internal",
    api_key_env="QDRANT_API_KEY",
    require_tls=True,
    timeout_seconds=20,
)

resolved = credentials.resolve()
assert resolved["api_key"]  # Never print or log the resolved credential.
```

The memory backend then uses those resolved values when constructing its SDK client. `MemoryGuard.memory_access_layer._managed_provider_config()` specifically strips `credentials` out of the adapter config and resolves them into the real provider connection parameters. This is important: the adapter config is not supposed to carry agent-supplied or request-derived secrets in `request.metadata`; credentials live in the host environment, a secret manager, or a KMS-backed application object.

A typical memory registration looks like this:

```python
from MemoryGuard.config import StoreConfig
from MemoryGuard.memory_access_layer import QdrantBackend

backend = QdrantBackend(
    collection="agent_memory",
    url="https://example-qdrant.internal",
    api_key=os.environ["QDRANT_API_KEY"],
)

registry = StoreRegistry()
registry.register(StoreConfig(
    store_id="agent-profile",
    store_type="vector",
    provider="qdrant",
    adapter=backend,
    memory_types=frozenset({"profile", "conversation"}),
    capabilities=frozenset({"read", "write", "update", "delete", "search"}),
    enabled=True,
))
```

Notice the flow clearly:

1. The host creates the adapter and resolves credentials.
2. The host registers the adapter in `StoreRegistry`.
3. `AgentSecurityOrchestrator.process()` receives a request and a trusted context.
4. The orchestrator calls `memory_access_layer.execute(request, context)`.
5. The memory gateway checks authorization and only then invokes the adapter method.

`AgentSecurityOrchestrator.process` does not inject adapter credentials from the request. It does not read credentials from `MemoryRequest.metadata`, `ToolRequest.arguments`, or `SecretAccessRequest`; that would be unsafe and would let the untrusted request influence provider access. The trusted identity/context is the only thing it validates before dispatch.

For secret material, the flow is different but equally strict. `SecretBroker` is the secret gateway, and it handles secret registration and usage through `SecretMaterial` and a `SecretVault`/key manager. `SecretMaterial.from_value(...)` creates runtime-only plaintext, which the broker immediately clears or encrypts and never persists in the request object. A `SecretAccessRequest` carries only an identifier, tenant, requester, tool, and purpose; it does not carry the secret value. See the complete registration and bounded-use example under the SecretGuard section below.

So the credential flow is:

- Memory adapters: app-owned credentials in adapter construction or environment resolution.
- Secret broker: `SecretMaterial` is passed only in trusted host code during registration/rotation; the request contains only metadata.
- `AgentSecurityOrchestrator.process`: validates prompt + trusted context, then dispatches to the proper gateway. It never pulls provider credentials from the request and never turns the agent into a secret owner.

## ToolGuard

```python
ToolGuard(registry=None, audit=None, llm_analyser=None, *, trusted_context=None)
```

| Argument | Meaning |
| --- | --- |
| `registry` | `ToolRegistry` mapping developer-owned `ToolDefinition` objects to Python callables. Unknown tools are denied. |
| `audit` | `ToolAuditStore` for encrypted audit data. Configure it with `TOOL_GUARD_KEY` or an explicit key; no built-in key is used. |
| `llm_analyser` | Optional callable `(serialized_payload, features) -> mapping` for pre-request and post-output analysis. Missing, malformed, or failed analysis fails to review/quarantine. No LLM is enabled by default. |
| `trusted_context` | Host-created default `ToolSecurityContext`; alternatively pass a context to each `execute` call. |

`ToolRegistry.register(definition, implementation)` binds one `ToolDefinition` to the real Python implementation. `ToolGuard.pre_guard(request)` evaluates the request without running the implementation. `ToolGuard.execute(request, context=None)` requires trusted identity, runs pre-checks, calls the implementation, checks its output, audits each stage, and returns a `ToolResult`. `ToolGuard.create_framework_tool(tool_id, context, operation=None)` creates a callable for an agent framework; it binds trusted identity and routes every call through `execute`.

`ToolDefinition` declares ID, name, description, purpose, allowed operations/resources, schemas, and risk metadata. `ToolRequest` carries request/agent/session/task IDs, tool ID, purpose, reason, arguments, and optional task/history context. Build identity from trusted host state. `execute(request, context=None)` returns `ToolResult`; its `decision` is `ALLOW_RESULT` when accepted, and rejected output is withheld. The current schema check validates required fields and declared top-level types, not full JSON Schema; validate high-impact constraints inside the tool too.

### Tool execution call and payload

The public operation is `ToolGuard.execute(request: ToolRequest, context=None) -> ToolResult`. Configure an encrypted audit store and register the callable before execution:

```python
import os

from aso import ToolAuditStore, ToolSecurityContext


def lookup_ticket(ticket_id: str, operation: str) -> dict:
    # Replace with the application's actual ticket service call.
    return {"ticket_id": ticket_id, "status": "open"}


registry = ToolRegistry()
registry.register(
    ToolDefinition(
        tool_id="ticket_lookup",
        name="Ticket lookup",
        description="Read a ticket status.",
        purpose="Look up a ticket requested by the current user.",
        input_schema={
            "type": "object",
            "properties": {
                "operation": {"type": "string"},
                "ticket_id": {"type": "string"},
            },
            "required": ["operation", "ticket_id"],
        },
        operations=frozenset({"read"}),
        allowed_resources=frozenset({"T-100"}),
        output_schema={"type": "object"},
    ),
    lookup_ticket,
)

tool_context = ToolSecurityContext(
    agent_id="agent-42",
    session_id="session-11",
    authorized_tools=frozenset({"ticket_lookup"}),
)
audit = ToolAuditStore(
    database_path="tool_guard.db",
    encryption_key=os.environ["TOOL_GUARD_KEY"],
)
guard = ToolGuard(registry=registry, audit=audit, trusted_context=tool_context)
request = ToolRequest(
    request_id="req-100",
    agent_id="agent-42",
    session_id="session-11",
    task_id="task-11",
    tool_id="ticket_lookup",
    purpose="Read the status of ticket T-100.",
    reason="The user asked for the ticket status.",
    arguments={"operation": "read", "ticket_id": "T-100"},
)
result = guard.execute(request, tool_context)
if result.decision.value != "ALLOW_RESULT":
    raise PermissionError(f"ToolGuard blocked the request: {result.reasons}")
print(result.data)
```

`execute` arguments:

| Argument | Required content |
| --- | --- |
| `request` | A `ToolRequest`. `tool_id` selects the registered definition/callable. Required IDs must be non-empty. Explain the purpose and reason, and provide only the operation arguments the callable needs. |
| `context` | Optional host-created `ToolSecurityContext`; if omitted, the guard's configured `trusted_context` is used. Missing or mismatched context is denied. |

`ToolRequest` fields:

| Field | What to put in it |
| --- | --- |
| `request_id` | Unique correlation ID for this invocation. |
| `agent_id`, `session_id`, `task_id` | Authenticated agent/session and current task IDs. `ToolGuard.execute(request, context)` checks agent, session, and tool against the host-created `ToolSecurityContext`; alternatively configure `trusted_context` on the guard. |
| `tool_id` | Exact ID registered in `ToolRegistry`. |
| `purpose`, `reason` | Human-readable, specific why the tool and this operation are needed. Empty values cause review. |
| `arguments` | Mapping passed to the callable as keyword arguments (unknown keys are filtered unless the callable accepts `**kwargs`). Include `operation` when the definition lists operations. |
| `task_context` | Optional bounded task background relevant to this invocation. |
| `previous_tool_context` | Optional sequence summarizing prior calls; chains longer than 50 are reviewed. |
| `timestamp` | Optional caller timestamp; if omitted, guard decisions use their own current timestamp. |

`ToolDefinition` fields and contents:

| Field | What to put in it |
| --- | --- |
| `tool_id`, `name`, `description`, `purpose` | Stable ID, human-readable name, what it does, and its intended security-approved use. The first four are required and non-empty. |
| `input_schema`, `output_schema` | Mapping describing input/output shape. Current input enforcement checks required fields and declared top-level property types; output enforcement checks only top-level `type`. Validate nested/full schemas in the implementation. |
| `expected_output` | Short description of the expected result used as context for output review. |
| `operations` | Allowed operation strings, compared to `request.arguments["operation"]` when set. |
| `side_effects`, `required_capabilities` | Descriptive declarations of effects and capabilities; do not assume these are independently enforced currently. |
| `allowed_resources` | Resource identifiers that must match the request's non-operation scalar argument values; use narrow IDs, not broad wildcards. |
| `forbidden_operations` | Values that must never appear among request argument values. |
| `sensitivity`, `risk_characteristics`, `execution_constraints` | Additional policy/context metadata. Enforce critical constraints inside the callable until the guard explicitly supports them. |

The definition's `operations`, `forbidden_operations`, and `allowed_resources` take part in deterministic pre-checks. The registered callable is run inside `execute`, then output inspection runs before returning `ToolResult`; a denied/quarantined result has no data. Supply `TOOL_GUARD_KEY` or an explicit key; ToolGuard does not create an insecure default key.

No fallback audit key exists: `ToolAuditStore` requires `TOOL_GUARD_KEY` or an explicit key. Its `record(decision, agent_id)`, `snapshot()`, and `close()` methods write, inspect, and close encrypted audit storage. Do not generate a different key on each startup; old audit rows cannot be decrypted with a replacement key.

To attach a tool to a framework agent, use the guard-created wrapper. It constructs the typed request, binds trusted identity, and raises instead of returning data if the guard rejects the call:

```python
guarded_lookup = guard.create_framework_tool(
    tool_id="ticket_lookup",
    context=tool_context,
    operation="read",
)
agent = orchestrator.create_agent(
    agent_name="support-agent",
    model_name="your-agent-model",
    developer_name="Example Engineering",
    description="Looks up support tickets.",
    tools=[guarded_lookup],
)
```

## SecretGuard

`SecretGuard()` has no constructor arguments. `evaluate_store(definition, permissions)` checks registration/storage policy. `evaluate_access(definition, permissions, request, status)` checks active status, type, operation, destination, exposure, and purpose, returning a decision and reason codes. It does not store or return plaintext.

The normal path uses `SecretBroker(repository, vault, permissions=None, guard=None)`. `SecretVault(repository, key_manager)` performs encrypted storage and bounded secret use. Production must inject a KMS/HSM-backed `KeyManager`; `LocalDevelopmentKeyManager` is development-only. `SecretMaterial.from_value(...)` is trusted registration/rotation input and is cleared by broker paths. `SecretAccessRequest` describes the operation without secret bytes. `SecretSecurityContext` is host-created and binds tenant, requester, agent, session, and authorized tool IDs.

Reads use `SecretBroker.execute_with_secret(request, context, callback)`. The callback receives a temporary `memoryview`; return only the minimum derived result, never the bytes. The broker checks trusted context and policy before callback and audits the event. Never log callback input, `SecretMaterial.value`, API keys, or environment values. The local key manager requires `SECRETGUARD_DEV_KEK_B64`; never use it for production.

### Complete secret service example

This example shows `SecretBroker` setup, the registration call's arguments, and a bounded read. Set `SECRETGUARD_DEV_KEK_B64` through a local secret manager before running this development example. In production, inject a KMS/HSM implementation of `KeyManager` instead.

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
vault = SecretVault(repository, LocalDevelopmentKeyManager())
broker = SecretBroker(repository, vault)

policy = SecretPermissions(
    allowed_use=True,
    allowed_type=frozenset({SecretType.OPENAI_API_KEY}),
    allowed_destination=frozenset({"vault", "openai-api"}),
    allowed_operations=frozenset({"store", "read", "update", "revoke", "delete"}),
    allowed_exposed=True,
)
secret_id, version = broker.register_secret(
    definition=SecretDefinition(
        name="support-agent OpenAI credential",
        secret_type=SecretType.OPENAI_API_KEY,
        source="host secret manager",
        operations=frozenset({"store", "read", "update", "revoke", "delete"}),
        destinations=frozenset({"openai-api"}),
        allowed=True,
        exposed=True,
    ),
    material=SecretMaterial.from_value(os.environ["OPENAI_API_KEY"]),
    tenant_id="tenant-7",
    permissions=policy,
)

trusted = SecretSecurityContext(
    tenant_id="tenant-7",
    requester="support-service",
    agent_id="agent-42",
    session_id="session-11",
    authorized_tools=frozenset({"chat_completion"}),
)
request = SecretAccessRequest(
    request_id=str(uuid.uuid4()),
    secret_id=secret_id,
    tenant_id="tenant-7",
    requester="support-service",
    agent_id="agent-42",
    session_id="session-11",
    tool_id="chat_completion",
    purpose="Authenticate this approved provider request.",
    operation="read",
    destination="openai-api",
    version=version,
)

def call_provider(secret_view):
    token = secret_view.tobytes().decode("utf-8")
    return provider_client.call(api_key=token)  # Return provider data, never the token.

safe_result = broker.execute_with_secret(request, trusted, call_provider)
```

`allowed_exposed=True` and `definition.exposed=True` explicitly permit plaintext to reach this callback. Leave both false unless the specific flow needs secret use. `rotate(request, trusted, SecretMaterial.from_value(new_value))` stores a new version subject to the same policy. `revoke(request, trusted)` disables access; `revoke(request, trusted, operation="delete")` removes the stored secret and versions. Close `repository` when the application shuts down.

### SecretBroker calls and payloads

`SecretBroker(repository, vault, permissions=None, guard=None)` composes the secret application. `repository` is a `SecretRepository` for metadata/ciphertext/audit persistence. `vault` is a `SecretVault` built with that repository and a `KeyManager`. `permissions` is a default deny-by-default `SecretPermissions` policy for secrets without a stored per-secret policy; `guard` is a `SecretGuard` policy evaluator. Normal registered secrets use their stored definition and permissions.

`SecretRepository(database_path="secret_guard.db")` creates SQLite tables for definitions, permissions, encrypted versions, and audit events; call `close()` at shutdown. `SecretVault(repository, key_manager)` performs encryption, decryption-for-callback, rotation, revocation, and deletion. Supply a production `KeyManager` backed by a KMS/HSM. Although vault methods exist, application and agent code should access them through `SecretBroker` so policy and audit checks are not skipped. A custom `KeyManager` implements `generate_dek`, `wrap_dek`, `unwrap_dek`, and `get_current_key_version`.

| Broker method | Arguments and contents |
| --- | --- |
| `register_secret(definition, material, tenant_id, permissions)` | `definition`: metadata/policy (`name`, `secret_type`, `source`, permitted `operations` and `destinations`, `allowed`, `exposed`, optional `secret_id`); `material`: trusted `SecretMaterial` bytes, cleared by the method; `tenant_id`: authenticated tenant; `permissions`: explicit policy. Returns `(secret_id, version)`. |
| `execute_with_secret(request, context, callback)` | `request`: `SecretAccessRequest` for the target/operation; `context`: host-authenticated `SecretSecurityContext`; `callback`: callable receiving a temporary `memoryview` to perform bounded use. Returns callback result, not the secret itself. |
| `rotate(request, context, material)` | Existing authorized secret request/context plus new `SecretMaterial`. Stores a new version and clears the material. |
| `revoke(request, context, operation="revoke")` | Authorized request/context; `operation` is `revoke` or `delete`. `revoke` marks the secret inactive; `delete` physically removes its metadata and stored versions for the tenant. |

`SecretAccessRequest` fields:

| Field | What to put in it |
| --- | --- |
| `request_id` | Unique audit/correlation ID. |
| `secret_id` | ID returned by `register_secret`; never use the secret value as an identifier. |
| `tenant_id`, `requester`, `agent_id`, `session_id` | Authenticated identity values; each must match the host-created context. |
| `tool_id` | Calling tool ID; must be in `context.authorized_tools`. |
| `purpose` | Specific business reason for the secret operation; required for access. |
| `operation` | Policy operation such as `read`, `write`, `update`, `delete`, or `revoke`, as configured in definition/permissions. |
| `destination` | Approved destination/use label checked against both definition and permissions. |
| `version` | Optional explicit secret version; `None` selects the current active version. |

`SecretSecurityContext` fields are `tenant_id`, `requester`, `agent_id`, `session_id`, and `authorized_tools`. Create it after application authentication and do not accept it from the agent. `SecretPermissions` fields are `unregistered` (whether unregistered requests can be quarantined), `allowed_use`, `allowed_type` (set of `SecretType` values), `allowed_destination`, `allowed_operations`, and `allowed_exposed` (explicit opt-in to plaintext reaching the authorized callback). Keep exposure disabled unless the specific flow requires it.

The `process` interface maps secret `read` to `execute_with_secret`, `write`/`update` to `rotate`, and `delete` to `revoke(operation="delete")`. It does not expose `register_secret` through an agent request; register secrets in trusted application setup. Direct broker calls should likewise be made by trusted host code, not by giving the agent a broker or vault handle.

## Alerting integration

ASO enforces fail-closed policies and returns a `QUARANTINE` decision when the request or result looks suspicious. The library does not ship a built-in mailer or transport layer. The host application should hook its own escalation path so developers are alerted when a quarantine occurs.

### SMTP email escalation

```python
import smtplib
from email.message import EmailMessage


def send_smtp_alert(subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "aso-alerts@example.com"
    msg["To"] = "security@example.com"
    msg.set_content(body)

    with smtplib.SMTP("smtp.example.com", 587) as smtp:
        smtp.starttls()
        smtp.login("smtp-user", "smtp-password")
        smtp.send_message(msg)


def maybe_alert(result) -> None:
    if getattr(result, "decision", "") == "QUARANTINE":
        send_smtp_alert(
            "ASO quarantine notice",
            f"decision={result.decision}\nreasons={getattr(result, 'reason_codes', ())}",
        )
```

Use this pattern when you want an email alert to go to the security team or the app owners. Keep the SMTP server and credentials in the host configuration, not inside the request.

### Slack escalation

```python
import json
import urllib.request


def send_slack_alert(webhook_url: str, result) -> None:
    payload = {
        "text": (
            "ASO quarantine alert\n"
            f"decision={result.decision}\n"
            f"reasons={getattr(result, 'reason_codes', ())}"
        )
    }
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        response.read()
```

This is suitable for a team channel or on-call room. It should be triggered only after ASO produces a quarantined decision or fails closed.

### Webhook-based escalation

```python
import json
import urllib.request


def send_webhook_alert(webhook_url: str, result) -> None:
    payload = {
        "event": "aso_quarantine",
        "request_id": getattr(result, "request_id", "unknown"),
        "decision": getattr(result, "decision", "UNKNOWN"),
        "reason_codes": list(getattr(result, "reason_codes", ())),
        "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        response.read()
```

Webhook-based escalation is useful for SIEM systems, incident platforms or a custom internal service that converts quarantine events into ticketing, paging or Slack/SMS notifications.

### Recommended pattern

```python
def handle_result(result) -> None:
    if getattr(result, "decision", "") == "QUARANTINE":
        send_slack_alert("https://hooks.slack.com/services/your/webhook", result)
        send_webhook_alert("https://internal.example.com/aso/alerts", result)
```

Use the result object from the guard or the orchestrator as the source of truth for escalation. Do not build escalation logic from untrusted agent input. The host should log, page, and retain the event securely.

## Operational Checklist

- Authenticate identities in the host and create trusted contexts there.
- Register only necessary tools and resources; put guards directly in front of actual operations.
- Test benign, adversarial, malformed, and unavailable-model cases.
- Configure timeouts, network restrictions, and application-level validation around providers.
- Keep audit databases and encryption keys outside agent-visible paths.
- Use KMS/HSM for production secrets; the bundled local key manager is development-only.
- Treat `ALLOW` as the result of implemented checks, not proof of safety.

