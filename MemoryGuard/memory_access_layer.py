"""Authorization-aware memory access interfaces and local persistence."""

from __future__ import annotations

import json
import hashlib
import importlib
import os
import sqlite3
import uuid
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from .config import (
    AgentRequest,
    AuditEvent,
    Decision,
    GuardDecision,
    MemoryRequest,
    Operation,
    ProviderCredentials,
    SecurityContext,
    StoreConfig,
)
from .memory_guard import CyberAI, MemoryGuard

DECISIONS = {"accept", "deny", "quarantine"}
VECTOR_PROVIDERS = {"qdrant", "pinecone", "weaviate", "milvus", "chroma", "faiss", "pgvector", "vespa"}


def _scoped_key(request: AgentRequest, memory_id: str) -> str:
    scope = json.dumps(
        [request.tenant_id, request.agent_id, str(memory_id)],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"aso-memory:{scope}"))


def _scoped_uuid(request: AgentRequest, memory_id: str) -> str:
    return _scoped_key(request, memory_id)


def _managed_provider_config(provider: str, config: dict[str, Any]) -> dict[str, Any]:
    """Resolve application credentials without placing secrets in adapter metadata."""
    credentials = config.pop("credentials", None)
    if credentials is None:
        return config
    if not isinstance(credentials, ProviderCredentials):
        raise TypeError("credentials must be an application-owned ProviderCredentials")
    if credentials.provider != provider:
        raise ValueError("credential provider does not match adapter provider")
    resolved = credentials.resolve()
    if resolved.get("endpoint"):
        config.setdefault("url", resolved["endpoint"])
    if resolved.get("api_key"):
        config.setdefault("api_key", resolved["api_key"])
    if resolved.get("access_key"):
        config.setdefault("access_key", resolved["access_key"])
    if resolved.get("secret_key"):
        config.setdefault("secret_key", resolved["secret_key"])
    if resolved.get("region"):
        config.setdefault("region", resolved["region"])
    config["timeout"] = resolved["timeout_seconds"]
    return config


class SDKUnavailable(RuntimeError):
    """Raised when an application-configured provider SDK is unavailable."""


class ApplicationManagedBackend(ABC):
    """Backend contract; credentials and clients stay inside the application."""

    @abstractmethod
    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any: ...


class SQLiteBackend(ApplicationManagedBackend):
    """Provider backend for an application-owned SQLite memory database.

    This connection is deliberately separate from ``DatabaseManager``. The
    latter is reserved for Memory Guard metadata and audit records.
    """

    def __init__(self, database_path: str | Path = "agent_memory.db") -> None:
        self.database_path = str(database_path)
        self._connection: sqlite3.Connection | None = None

    def _connection_for(self) -> sqlite3.Connection:
        if self._connection is None:
            self._connection = sqlite3.connect(self.database_path)
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_items (
                    memory_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL DEFAULT '',
                    agent_id TEXT NOT NULL,
                    encrypted_payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            columns = {row[1] for row in self._connection.execute("PRAGMA table_info(memory_items)")}
            if "tenant_id" not in columns:
                self._connection.execute("ALTER TABLE memory_items ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''")
            self._connection.commit()
        return self._connection

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        connection = self._connection_for()
        scoped_id = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            connection.execute(
                "INSERT OR REPLACE INTO memory_items (memory_id, tenant_id, agent_id, encrypted_payload, updated_at) VALUES (?, ?, ?, ?, ?)",
                (scoped_id, request.tenant_id, request.agent_id, request.data, datetime.now(timezone.utc).isoformat()),
            )
            connection.commit()
            return None
        if operation in {"read", "search"}:
            row = connection.execute(
                "SELECT encrypted_payload FROM memory_items WHERE memory_id = ? AND tenant_id = ? AND agent_id = ?",
                (scoped_id, request.tenant_id, request.agent_id),
            ).fetchone()
            return row[0] if row else None
        if operation == "delete":
            cursor = connection.execute(
                "DELETE FROM memory_items WHERE memory_id = ? AND tenant_id = ? AND agent_id = ?",
                (scoped_id, request.tenant_id, request.agent_id),
            )
            connection.commit()
            return cursor.rowcount > 0
        raise ValueError(f"unsupported SQLite operation: {operation}")

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None


def _json_payload(request: AgentRequest) -> str:
    return json.dumps(request.data, ensure_ascii=False, separators=(",", ":"))


def _encode_backend_payload(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _decode_backend_payload(value: str) -> Any:
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


class QdrantBackend(ApplicationManagedBackend):
    def __init__(self, collection: str = "memory", url: str | None = None, api_key: str | None = None) -> None:
        self.collection = collection
        self.url = url or os.environ.get("QDRANT_URL")
        self.api_key = api_key or os.environ.get("QDRANT_API_KEY")
        try:
            client_class = importlib.import_module("qdrant_client").QdrantClient
        except ImportError as error:
            raise SDKUnavailable("install qdrant-client for QdrantBackend") from error
        if not self.url:
            raise SDKUnavailable("QDRANT_URL is required")
        self._client = client_class(url=self.url, api_key=self.api_key)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        client = self._client
        scoped_id = _scoped_uuid(request, memory_id)
        if operation in {"write", "update"}:
            vector = AgentDB._embedding(request.data)
            payload = {"ciphertext": request.data, "agent_id": request.agent_id, "tenant_id": request.tenant_id}
            point = importlib.import_module("qdrant_client.http.models").PointStruct(
                id=scoped_id, vector=vector, payload=payload
            )
            client.upsert(collection_name=self.collection, points=[point], wait=True)
            return None
        if operation in {"read", "search"}:
            result = client.retrieve(collection_name=self.collection, ids=[scoped_id], with_payload=True)
            return result[0].payload.get("ciphertext") if result else None
        if operation == "delete":
            client.delete(collection_name=self.collection, points_selector=[scoped_id], wait=True)
            return True
        raise ValueError(f"unsupported Qdrant operation: {operation}")


class PineconeBackend(ApplicationManagedBackend):
    def __init__(self, index: str = "memory", namespace: str = "default", api_key: str | None = None) -> None:
        self.index_name = index
        self.namespace = namespace
        self.api_key = api_key or os.environ.get("PINECONE_API_KEY")
        try:
            pinecone = importlib.import_module("pinecone")
        except ImportError as error:
            raise SDKUnavailable("install pinecone for PineconeBackend") from error
        if not self.api_key:
            raise SDKUnavailable("PINECONE_API_KEY is required")
        self._index = pinecone.Pinecone(api_key=self.api_key).Index(self.index_name)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        index = self._index
        scoped_id = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            index.upsert([(scoped_id, AgentDB._embedding(request.data), {
                "ciphertext": request.data, "agent_id": request.agent_id, "tenant_id": request.tenant_id,
            })], namespace=self.namespace)
            return None
        if operation in {"read", "search"}:
            result = index.fetch([scoped_id], namespace=self.namespace)
            vector = result.vectors.get(scoped_id)
            return vector.metadata.get("ciphertext") if vector else None
        if operation == "delete":
            index.delete(ids=[scoped_id], namespace=self.namespace)
            return True
        raise ValueError(f"unsupported Pinecone operation: {operation}")


class S3Backend(ApplicationManagedBackend):
    def __init__(self, bucket: str, prefix: str = "memory", region: str | None = None) -> None:
        self.bucket, self.prefix, self.region = bucket, prefix.strip("/"), region
        try:
            boto3 = importlib.import_module("boto3")
        except ImportError as error:
            raise SDKUnavailable("install boto3 for S3Backend") from error
        self._client = boto3.client("s3", region_name=self.region)

    def _key(self, memory_id: str) -> str:
        return f"{self.prefix}/{memory_id}.json"

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        client, key = self._client, self._key(_scoped_key(request, memory_id))
        if operation in {"write", "update"}:
            client.put_object(Bucket=self.bucket, Key=key, Body=_json_payload(request).encode(), ContentType="application/json", ServerSideEncryption="AES256")
            return None
        if operation in {"read", "search"}:
            try:
                return json.loads(client.get_object(Bucket=self.bucket, Key=key)["Body"].read().decode())
            except Exception as error:
                response = getattr(error, "response", {})
                code = response.get("Error", {}).get("Code")
                if code in {"NoSuchKey", "404"}:
                    return None
                raise
        if operation == "delete":
            client.delete_object(Bucket=self.bucket, Key=key)
            return True
        raise ValueError(f"unsupported S3 operation: {operation}")


class RedisBackend(ApplicationManagedBackend):
    def __init__(self, namespace: str = "memory", url: str | None = None) -> None:
        self.namespace = namespace.strip(":")
        self.url = url or os.environ.get("REDIS_URL")
        try:
            redis = importlib.import_module("redis")
        except ImportError as error:
            raise SDKUnavailable("install redis for RedisBackend") from error
        if not self.url:
            raise SDKUnavailable("REDIS_URL is required")
        self._client = redis.Redis.from_url(self.url, decode_responses=True)
        self._client.ping()

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        client, key = self._client, f"{self.namespace}:{_scoped_key(request, memory_id)}"
        if operation in {"write", "update"}:
            client.set(key, _json_payload(request))
            return None
        if operation in {"read", "search"}:
            value = client.get(key)
            return json.loads(value) if value else None
        if operation == "delete":
            return bool(client.delete(key))
        raise ValueError(f"unsupported Redis operation: {operation}")


class MongoBackend(ApplicationManagedBackend):
    def __init__(self, database: str = "memory", collection: str = "items", uri: str | None = None) -> None:
        self.database, self.collection_name = database, collection
        self.uri = uri or os.environ.get("MONGODB_URI")
        try:
            MongoClient = importlib.import_module("pymongo").MongoClient
        except ImportError as error:
            raise SDKUnavailable("install pymongo for MongoBackend") from error
        if not self.uri:
            raise SDKUnavailable("MONGODB_URI is required")
        self._client = MongoClient(self.uri, serverSelectionTimeoutMS=10000)
        self._client.admin.command("ping")
        self._collection = self._client[self.database][self.collection_name]

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        collection = self._collection
        scoped_id = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            collection.replace_one(
                {"_id": scoped_id},
                {"_id": scoped_id, "tenant_id": request.tenant_id, "agent_id": request.agent_id, "payload": request.data},
                upsert=True,
            )
            return None
        if operation in {"read", "search"}:
            item = collection.find_one({"_id": scoped_id, "tenant_id": request.tenant_id, "agent_id": request.agent_id})
            return item.get("payload") if item else None
        if operation == "delete":
            return collection.delete_one({"_id": scoped_id, "tenant_id": request.tenant_id, "agent_id": request.agent_id}).deleted_count > 0
        raise ValueError(f"unsupported MongoDB operation: {operation}")


class DynamoDBBackend(ApplicationManagedBackend):
    def __init__(self, table: str, region: str | None = None) -> None:
        self.table_name, self.region = table, region
        try:
            boto3 = importlib.import_module("boto3")
        except ImportError as error:
            raise SDKUnavailable("install boto3 for DynamoDBBackend") from error
        self._table = boto3.resource("dynamodb", region_name=self.region).Table(self.table_name)
        self._table.load()

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        table = self._table
        scoped_id = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            table.put_item(Item={
                "memory_id": scoped_id, "tenant_id": request.tenant_id,
                "agent_id": request.agent_id, "payload": request.data,
            })
            return None
        if operation in {"read", "search"}:
            item = table.get_item(Key={"memory_id": scoped_id}).get("Item", {})
            if item.get("tenant_id") != request.tenant_id or item.get("agent_id") != request.agent_id:
                return None
            return item.get("payload")
        if operation == "delete":
            item = table.get_item(Key={"memory_id": scoped_id}).get("Item", {})
            if item.get("tenant_id") != request.tenant_id or item.get("agent_id") != request.agent_id:
                return False
            table.delete_item(Key={"memory_id": scoped_id})
            return True
        raise ValueError(f"unsupported DynamoDB operation: {operation}")


class ElasticsearchBackend(ApplicationManagedBackend):
    def __init__(self, index: str = "memory", url: str | None = None, api_key: str | None = None) -> None:
        self.index, self.url = index, url or os.environ.get("ELASTICSEARCH_URL")
        self.api_key = api_key or os.environ.get("ELASTICSEARCH_API_KEY")
        try:
            Elasticsearch = importlib.import_module("elasticsearch").Elasticsearch
        except ImportError as error:
            raise SDKUnavailable("install elasticsearch for ElasticsearchBackend") from error
        if not self.url:
            raise SDKUnavailable("ELASTICSEARCH_URL is required")
        self._client = Elasticsearch(self.url, api_key=self.api_key, request_timeout=10)
        if not self._client.ping():
            raise SDKUnavailable("Elasticsearch endpoint is unavailable")

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        client = self._client
        scoped_id = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            client.index(index=self.index, id=scoped_id, document={
                "payload": request.data, "tenant_id": request.tenant_id, "agent_id": request.agent_id,
            }, refresh=True)
            return None
        if operation in {"read", "search"}:
            try:
                source = client.get(index=self.index, id=scoped_id)["_source"]
                if source.get("tenant_id") != request.tenant_id or source.get("agent_id") != request.agent_id:
                    return None
                return source.get("payload")
            except Exception:
                return None
        if operation == "delete":
            try:
                source = client.get(index=self.index, id=scoped_id)["_source"]
            except Exception:
                return False
            if source.get("tenant_id") != request.tenant_id or source.get("agent_id") != request.agent_id:
                return False
            client.delete(index=self.index, id=scoped_id, refresh=True, ignore=[404])
            return True
        raise ValueError(f"unsupported Elasticsearch operation: {operation}")


def _required_module(module_name: str, install_name: str | None = None) -> Any:
    try:
        return importlib.import_module(module_name)
    except ImportError as error:
        raise SDKUnavailable(f"install {install_name or module_name} before starting this provider") from error


class WeaviateBackend(ApplicationManagedBackend):
    def __init__(self, collection: str, url: str, api_key: str | None = None) -> None:
        module = _required_module("weaviate", "weaviate-client")
        auth = module.auth.AuthApiKey(api_key) if api_key else None
        self.client = module.connect_to_custom(url, auth_credentials=auth)
        self.collection = self.client.collections.get(collection)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        scoped_id = _scoped_uuid(request, memory_id)
        if operation in {"write", "update"}:
            properties = {
                "ciphertext": request.data,
                "agent_id": request.agent_id,
                "tenant_id": request.tenant_id,
            }
            self.collection.data.insert(properties=properties, uuid=scoped_id)
            return None
        if operation in {"read", "search"}:
            item = self.collection.query.fetch_object_by_id(uuid=scoped_id)
            if item is None:
                return None
            properties = item.properties
            if properties.get("agent_id") != request.agent_id or properties.get("tenant_id") != request.tenant_id:
                return None
            return properties.get("ciphertext")
        if operation == "delete":
            item = self.collection.query.fetch_object_by_id(uuid=scoped_id)
            if item is None:
                return False
            properties = item.properties
            if properties.get("agent_id") != request.agent_id or properties.get("tenant_id") != request.tenant_id:
                return False
            self.collection.data.delete_by_id(scoped_id)
            return True
        raise ValueError(f"unsupported Weaviate operation: {operation}")


class MilvusBackend(ApplicationManagedBackend):
    def __init__(self, collection: str, uri: str, token: str | None = None) -> None:
        module = _required_module("pymilvus")
        module.connections.connect(alias="default", uri=uri, token=token)
        self.module, self.collection_name = module, collection
        self.collection = module.Collection(collection)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        scoped_id = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            vector = AgentDB._embedding(request.data)
            payload = json.dumps({
                "ciphertext": request.data,
                "tenant_id": request.tenant_id,
                "agent_id": request.agent_id,
            }, separators=(",", ":"))
            self.collection.insert([[scoped_id, vector, payload]])
            self.collection.flush()
            return None
        if operation in {"read", "search"}:
            rows = self.collection.query(expr=f'id == "{scoped_id}"', output_fields=["payload"])
            if not rows:
                return None
            stored = json.loads(rows[0].get("payload", "{}"))
            if stored.get("agent_id") != request.agent_id or stored.get("tenant_id") != request.tenant_id:
                return None
            return stored.get("ciphertext")
        if operation == "delete":
            rows = self.collection.query(expr=f'id == "{scoped_id}"', output_fields=["payload"])
            if not rows:
                return False
            stored = json.loads(rows[0].get("payload", "{}"))
            if stored.get("agent_id") != request.agent_id or stored.get("tenant_id") != request.tenant_id:
                return False
            self.collection.delete(f'id == "{scoped_id}"')
            return True
        raise ValueError(f"unsupported Milvus operation: {operation}")


class ChromaBackend(ApplicationManagedBackend):
    def __init__(self, collection: str, host: str, port: int = 8000) -> None:
        module = _required_module("chromadb")
        self.collection = module.HttpClient(host=host, port=port).get_or_create_collection(collection)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        scoped_id = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            self.collection.upsert(
                ids=[scoped_id],
                documents=[json.dumps(request.data, ensure_ascii=False)],
                metadatas=[{"agent_id": request.agent_id, "tenant_id": request.tenant_id}],
            )
            return None
        if operation in {"read", "search"}:
            result = self.collection.get(ids=[scoped_id], include=["documents", "metadatas"])
            if not result.get("documents"):
                return None
            metadata = result.get("metadatas", [{}])[0] or {}
            if metadata.get("agent_id") != request.agent_id or metadata.get("tenant_id") != request.tenant_id:
                return None
            return json.loads(result["documents"][0])
        if operation == "delete":
            result = self.collection.get(ids=[scoped_id], include=["metadatas"])
            if not result.get("ids"):
                return False
            metadata = result.get("metadatas", [{}])[0] or {}
            if metadata.get("agent_id") != request.agent_id or metadata.get("tenant_id") != request.tenant_id:
                return False
            self.collection.delete(ids=[scoped_id])
            return True
        raise ValueError(f"unsupported Chroma operation: {operation}")


class FaissBackend(ApplicationManagedBackend):
    def __init__(self, index_path: str, dimensions: int = 32) -> None:
        module = _required_module("faiss", "faiss-cpu")
        self.module, self.index_path, self.dimensions = module, index_path, dimensions
        self.records_path = Path(f"{index_path}.records.json")
        self.records: dict[str, dict[str, Any]] = {}
        if self.records_path.exists():
            self.records = json.loads(self.records_path.read_text(encoding="utf-8"))
        self.index = module.IndexFlatL2(dimensions)
        self._rebuild_index()

    def _rebuild_index(self) -> None:
        import numpy

        self.index = self.module.IndexFlatL2(self.dimensions)
        self.record_ids = sorted(self.records)
        if self.record_ids:
            vectors = [self.records[key]["vector"] for key in self.record_ids]
            self.index.add(numpy.asarray(vectors, dtype="float32"))

    def _persist(self) -> None:
        self.records_path.parent.mkdir(parents=True, exist_ok=True)
        self.records_path.write_text(json.dumps(self.records), encoding="utf-8")
        self.module.write_index(self.index, str(self.index_path))

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        scoped_id = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            self.records[scoped_id] = {
                "tenant_id": request.tenant_id,
                "agent_id": request.agent_id,
                "payload": request.data,
                "vector": AgentDB._embedding(request.data, self.dimensions),
            }
            self._rebuild_index()
            self._persist()
            return None
        if operation in {"read", "search"}:
            record = self.records.get(scoped_id)
            if not record or record["tenant_id"] != request.tenant_id or record["agent_id"] != request.agent_id:
                return None
            return record["payload"]
        if operation == "delete":
            record = self.records.get(scoped_id)
            if not record or record["tenant_id"] != request.tenant_id or record["agent_id"] != request.agent_id:
                return False
            del self.records[scoped_id]
            self._rebuild_index()
            self._persist()
            return True
        raise ValueError(f"unsupported FAISS operation: {operation}")


class SQLBackend(ApplicationManagedBackend):
    def __init__(self, url: str, table: str = "agent_memory", schema: str | None = None) -> None:
        if not url:
            raise SDKUnavailable("a SQLAlchemy database URL is required")
        sqlalchemy = _required_module("sqlalchemy")
        self.engine = sqlalchemy.create_engine(url, pool_pre_ping=True, future=True)
        self.sqlalchemy = sqlalchemy
        metadata = sqlalchemy.MetaData()
        self.table = sqlalchemy.Table(
            table,
            metadata,
            sqlalchemy.Column("memory_id", sqlalchemy.String(36), primary_key=True),
            sqlalchemy.Column("agent_id", sqlalchemy.String(255), nullable=False),
            sqlalchemy.Column("payload", sqlalchemy.Text, nullable=False),
            sqlalchemy.Column("updated_at", sqlalchemy.String(64), nullable=False),
            schema=schema,
        )
        with self.engine.begin() as connection:
            metadata.create_all(connection)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        table = self.table
        scoped_id = _scoped_key(request, memory_id)
        select = self.sqlalchemy.select
        if operation in {"write", "update"}:
            with self.engine.begin() as connection:
                existing = connection.execute(
                    select(table.c.memory_id).where(table.c.memory_id == scoped_id)
                ).first()
                values = {
                    "agent_id": request.agent_id,
                    "payload": _encode_backend_payload(request.data),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
                if existing:
                    connection.execute(table.update().where(table.c.memory_id == scoped_id).values(**values))
                else:
                    connection.execute(table.insert().values(memory_id=scoped_id, **values))
            return None
        if operation in {"read", "search"}:
            with self.engine.connect() as connection:
                row = connection.execute(
                    select(table.c.payload).where(
                        table.c.memory_id == scoped_id,
                        table.c.agent_id == request.agent_id,
                    )
                ).first()
            return _decode_backend_payload(row[0]) if row else None
        if operation == "delete":
            with self.engine.begin() as connection:
                result = connection.execute(
                    table.delete().where(
                        table.c.memory_id == scoped_id,
                        table.c.agent_id == request.agent_id,
                    )
                )
            return result.rowcount > 0
        raise ValueError(f"unsupported SQL operation: {operation}")


class CouchDBBackend(ApplicationManagedBackend):
    def __init__(self, database: str, url: str, username: str, password: str) -> None:
        module = _required_module("couchdb")
        self.database = module.Server(url, auth=(username, password))[database]

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        scoped_id = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            document = self.database.get(scoped_id)
            if document:
                document.update({"agent_id": request.agent_id, "tenant_id": request.tenant_id, "payload": request.data})
                self.database.save(document)
            else:
                self.database.save({"_id": scoped_id, "agent_id": request.agent_id, "tenant_id": request.tenant_id, "payload": request.data})
            return None
        if operation in {"read", "search"}:
            document = self.database.get(scoped_id)
            if not document or document.get("agent_id") != request.agent_id or document.get("tenant_id") != request.tenant_id:
                return None
            return document.get("payload")
        if operation == "delete":
            document = self.database.get(scoped_id)
            if not document or document.get("agent_id") != request.agent_id or document.get("tenant_id") != request.tenant_id:
                return False
            self.database.delete(document)
            return bool(document)
        raise ValueError(f"unsupported CouchDB operation: {operation}")


class FirestoreBackend(ApplicationManagedBackend):
    def __init__(self, collection: str) -> None:
        firestore = _required_module("google.cloud.firestore")
        self.document = firestore.Client().collection(collection)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        document = self.document.document(_scoped_key(request, memory_id))
        if operation in {"write", "update"}:
            document.set({"tenant_id": request.tenant_id, "agent_id": request.agent_id, "payload": request.data})
            return None
        if operation in {"read", "search"}:
            snapshot = document.get()
            stored = snapshot.to_dict() if snapshot.exists else None
            if not stored or stored.get("agent_id") != request.agent_id or stored.get("tenant_id") != request.tenant_id:
                return None
            return stored.get("payload")
        if operation == "delete":
            snapshot = document.get()
            stored = snapshot.to_dict() if snapshot.exists else None
            if not stored or stored.get("agent_id") != request.agent_id or stored.get("tenant_id") != request.tenant_id:
                return False
            document.delete()
            return True
        raise ValueError(f"unsupported Firestore operation: {operation}")


class ValkeyBackend(RedisBackend):
    def __init__(self, namespace: str = "memory", url: str | None = None) -> None:
        self.namespace = namespace.strip(":")
        self.url = url or os.environ.get("VALKEY_URL")
        try:
            module = importlib.import_module("valkey")
            client_type = module.Valkey
        except ImportError:
            try:
                module = importlib.import_module("redis")
                client_type = module.Redis
            except ImportError as error:
                raise SDKUnavailable("install valkey or redis for ValkeyBackend") from error
        if not self.url:
            raise SDKUnavailable("VALKEY_URL is required")
        self._client = client_type.from_url(self.url, decode_responses=True)
        self._client.ping()


class MemcachedBackend(ApplicationManagedBackend):
    def __init__(self, host: str, port: int = 11211) -> None:
        module = _required_module("pymemcache.client")
        self.client = module.base.Client((host, port), connect_timeout=10, timeout=10)
        self.client.version()

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        key = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            self.client.set(key, _json_payload(request).encode())
            return None
        if operation in {"read", "search"}:
            value = self.client.get(key)
            return json.loads(value.decode()) if value else None
        if operation == "delete":
            return bool(self.client.delete(key))
        raise ValueError(f"unsupported Memcached operation: {operation}")


class Neo4jBackend(ApplicationManagedBackend):
    def __init__(self, uri: str, username: str, password: str) -> None:
        module = _required_module("neo4j")
        self.driver = module.GraphDatabase.driver(uri, auth=(username, password), connection_timeout=10)
        self.driver.verify_connectivity()

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        scoped_id = _scoped_key(request, memory_id)
        with self.driver.session() as session:
            if operation in {"write", "update"}:
                session.run(
                    "MERGE (m:Memory {id: $id}) SET m.agent_id=$agent, m.tenant_id=$tenant, m.payload=$payload",
                    id=scoped_id, agent=request.agent_id, tenant=request.tenant_id, payload=request.data,
                ).consume()
                return None
            if operation in {"read", "search"}:
                record = session.run(
                    "MATCH (m:Memory {id: $id, agent_id: $agent, tenant_id: $tenant}) RETURN m.payload AS payload",
                    id=scoped_id, agent=request.agent_id, tenant=request.tenant_id,
                ).single()
                return record["payload"] if record else None
            if operation == "delete":
                result = session.run(
                    "MATCH (m:Memory {id: $id, agent_id: $agent, tenant_id: $tenant}) WITH m DETACH DELETE m RETURN count(*) AS deleted",
                    id=scoped_id, agent=request.agent_id, tenant=request.tenant_id,
                ).single()
                return bool(result and result["deleted"])
        raise ValueError(f"unsupported Neo4j operation: {operation}")


class NeptuneBackend(Neo4jBackend):
    def __init__(self, uri: str, username: str | None = None, password: str | None = None) -> None:
        module = _required_module("neo4j")
        auth = (username, password) if username and password else None
        self.driver = module.GraphDatabase.driver(
            uri,
            auth=auth,
            connection_timeout=10,
            encrypted=True,
        )
        self.driver.verify_connectivity()


class ArangoBackend(ApplicationManagedBackend):
    def __init__(self, url: str, database: str, username: str, password: str, collection: str = "memory") -> None:
        module = _required_module("arango")
        self.collection = module.ArangoClient(hosts=url).db(database, username=username, password=password).collection(collection)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        scoped_id = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            self.collection.insert({
                "_key": scoped_id, "tenant_id": request.tenant_id,
                "agent_id": request.agent_id, "payload": request.data,
            }, overwrite=True)
            return None
        if operation in {"read", "search"}:
            item = self.collection.get(scoped_id)
            if not item or item.get("agent_id") != request.agent_id or item.get("tenant_id") != request.tenant_id:
                return None
            return item.get("payload")
        if operation == "delete":
            item = self.collection.get(scoped_id)
            if not item or item.get("agent_id") != request.agent_id or item.get("tenant_id") != request.tenant_id:
                return False
            self.collection.delete(scoped_id, ignore_missing=True)
            return True
        raise ValueError(f"unsupported ArangoDB operation: {operation}")


class TigerGraphBackend(ApplicationManagedBackend):
    def __init__(self, host: str, username: str, password: str, graph: str, vertex_type: str = "Memory") -> None:
        module = _required_module("pyTigerGraph")
        self.client = module.TigerGraphConnection(host=host, username=username, password=password, graphname=graph)
        self.client.gsql("INTERPRET QUERY () FOR GRAPH %s { PRINT 1; }" % graph)
        self.vertex_type = vertex_type

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        scoped_id = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            self.client.upsertVertex(self.vertex_type, scoped_id, {
                "agent_id": request.agent_id,
                "tenant_id": request.tenant_id,
                "payload": request.data,
            })
            return None
        if operation in {"read", "search"}:
            result = self.client.getVertex(self.vertex_type, scoped_id)
            if not result:
                return None
            attributes = result.get("attributes", result)
            if attributes.get("agent_id") != request.agent_id or attributes.get("tenant_id") != request.tenant_id:
                return None
            return attributes.get("payload")
        if operation == "delete":
            result = self.client.getVertex(self.vertex_type, scoped_id)
            if not result:
                return False
            attributes = result.get("attributes", result)
            if attributes.get("agent_id") != request.agent_id or attributes.get("tenant_id") != request.tenant_id:
                return False
            self.client.delVerticesById(self.vertex_type, [scoped_id])
            return True
        raise ValueError(f"unsupported TigerGraph operation: {operation}")


class LangGraphBackend(ApplicationManagedBackend):
    def __init__(self, graph: Any) -> None:
        if graph is None or not hasattr(graph, "invoke"):
            raise ValueError("an application-owned compiled LangGraph is required")
        self.graph = graph

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        return self.graph.invoke({
            "operation": operation,
            "memory_id": _scoped_key(request, memory_id),
            "payload": request.data,
            "agent_id": request.agent_id,
            "tenant_id": request.tenant_id,
        })


class SolrBackend(ApplicationManagedBackend):
    def __init__(self, url: str, core: str) -> None:
        module = _required_module("pysolr")
        self.client = module.Solr(f"{url.rstrip('/')}/{core}", timeout=10)
        self.client.ping()

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        scoped_id = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            self.client.add([{
                "id": scoped_id, "agent_id_s": request.agent_id,
                "tenant_id_s": request.tenant_id, "payload_s": json.dumps(request.data),
            }], commit=True)
            return None
        if operation in {"read", "search"}:
            results = self.client.search(
                f'id:"{scoped_id}" AND agent_id_s:"{request.agent_id}" AND tenant_id_s:"{request.tenant_id}"',
                rows=1,
            )
            return json.loads(results.docs[0]["payload_s"]) if results.docs else None
        if operation == "delete":
            self.client.delete(q=f'id:"{scoped_id}" AND agent_id_s:"{request.agent_id}" AND tenant_id_s:"{request.tenant_id}"', commit=True)
            return True
        raise ValueError(f"unsupported Solr operation: {operation}")


class OpenSearchBackend(ElasticsearchBackend):
    def __init__(self, index: str, url: str, api_key: str | None = None) -> None:
        try:
            module = importlib.import_module("opensearchpy")
        except ImportError as error:
            raise SDKUnavailable("install opensearch-py for OpenSearchBackend") from error
        self.index = index
        self._client = module.OpenSearch(hosts=[url], http_auth=(api_key, "") if api_key else None, timeout=10)
        if not self._client.ping():
            raise SDKUnavailable("OpenSearch endpoint is unavailable")


class VespaBackend(ApplicationManagedBackend):
    """Small document CRUD adapter for Vespa's HTTP document API."""

    def __init__(
        self,
        url: str,
        schema: str = "memory",
        namespace: str = "aso",
        timeout: float = 10,
        api_key: str | None = None,
    ) -> None:
        if not url:
            raise SDKUnavailable("VESPA_URL is required")
        self.url = url.rstrip("/")
        self.schema = schema
        self.namespace = namespace
        self.timeout = timeout
        self.api_key = api_key

    def _document_url(self, memory_id: str) -> str:
        doc_id = urllib.parse.quote(memory_id, safe="")
        return f"{self.url}/document/v1/{self.namespace}/{self.schema}/docid/{doc_id}"

    def _request(self, method: str, memory_id: str, body: dict[str, Any] | None = None) -> Any:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(
            self._document_url(memory_id),
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = response.read()
                return json.loads(payload) if payload else {}
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        scoped_id = _scoped_key(request, memory_id)
        if operation in {"write", "update"}:
            self._request("PUT", scoped_id, {"fields": {
                "payload": request.data,
                "agent_id": request.agent_id,
                "tenant_id": request.tenant_id,
            }})
            return None
        if operation in {"read", "search"}:
            result = self._request("GET", scoped_id)
            fields = result.get("fields", {}) if result else {}
            if fields.get("agent_id") != request.agent_id or fields.get("tenant_id") != request.tenant_id:
                return None
            return fields.get("payload")
        if operation == "delete":
            result = self._request("GET", scoped_id)
            fields = result.get("fields", {}) if result else {}
            if fields.get("agent_id") != request.agent_id or fields.get("tenant_id") != request.tenant_id:
                return False
            self._request("DELETE", scoped_id)
            return True
        raise ValueError(f"unsupported Vespa operation: {operation}")


class GCSBackend(ApplicationManagedBackend):
    def __init__(self, bucket: str, prefix: str = "memory") -> None:
        storage = _required_module("google.cloud.storage")
        self.bucket = storage.Client().bucket(bucket)
        self.prefix = prefix.strip("/")

    def _blob(self, memory_id: str):
        return self.bucket.blob(f"{self.prefix}/{memory_id}.json")

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        blob = self._blob(_scoped_key(request, memory_id))
        if operation in {"write", "update"}:
            blob.upload_from_string(_json_payload(request), content_type="application/json")
            return None
        if operation in {"read", "search"}:
            try:
                return json.loads(blob.download_as_text())
            except Exception as error:
                not_found = getattr(importlib.import_module("google.api_core.exceptions"), "NotFound")
                if not isinstance(error, not_found):
                    raise
                return None
        if operation == "delete":
            blob.delete()
            return True
        raise ValueError(f"unsupported GCS operation: {operation}")


class AzureBlobBackend(ApplicationManagedBackend):
    def __init__(self, account_url: str, container: str, credential: str) -> None:
        module = _required_module("azure.storage.blob")
        self.container = module.BlobServiceClient(account_url=account_url, credential=credential).get_container_client(container)

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        blob = self.container.get_blob_client(f"{_scoped_key(request, memory_id)}.json")
        if operation in {"write", "update"}:
            blob.upload_blob(_json_payload(request).encode(), overwrite=True)
            return None
        if operation in {"read", "search"}:
            try:
                return json.loads(blob.download_blob().readall().decode())
            except Exception as error:
                not_found = getattr(importlib.import_module("azure.core.exceptions"), "ResourceNotFoundError")
                if not isinstance(error, not_found):
                    raise
                return None
        if operation == "delete":
            blob.delete_blob(delete_snapshots="include")
            return True
        raise ValueError(f"unsupported Azure Blob operation: {operation}")


class FileBackend(ApplicationManagedBackend):
    def __init__(self, path: str | Path, format_name: str) -> None:
        self.path, self.format_name = Path(path), format_name
        if self.path.suffix:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self.path.mkdir(parents=True, exist_ok=True)

    def _record_path(self, scoped_id: str) -> Path:
        if self.path.suffix:
            return self.path.with_name(f"{self.path.stem}-{scoped_id}{self.path.suffix}")
        extension = {"json": ".json", "yaml": ".yaml", "csv": ".csv", "txt": ".txt"}[self.format_name]
        return self.path / f"{scoped_id}{extension}"

    def execute(self, operation: str, request: AgentRequest, memory_id: str) -> Any:
        path = self._record_path(_scoped_key(request, memory_id))
        if operation in {"write", "update"}:
            data = request.data
            if self.format_name == "json": text = json.dumps(data, ensure_ascii=False)
            elif self.format_name == "yaml": text = _required_module("yaml").safe_dump(data)
            elif self.format_name == "csv":
                import csv, io
                output = io.StringIO(); csv.writer(output).writerow([json.dumps(data, ensure_ascii=False)]); text = output.getvalue()
            else: text = str(data)
            path.write_text(text, encoding="utf-8")
            return None
        if operation in {"read", "search"}:
            if not path.exists():
                return None
            text = path.read_text(encoding="utf-8")
            if self.format_name == "json": return json.loads(text)
            if self.format_name == "yaml": return _required_module("yaml").safe_load(text)
            if self.format_name == "csv":
                import csv, io
                row = next(csv.reader(io.StringIO(text)), None)
                return json.loads(row[0]) if row else None
            return text
        if operation == "delete":
            existed = path.exists()
            path.unlink(missing_ok=True)
            return existed
        raise ValueError(f"unsupported file operation: {operation}")


@dataclass(frozen=True)
class OperationReceipt:
    """Safe result returned to the caller; guard decisions stay internal."""

    operation_id: str
    completed: bool
    data: Any = None


class PayloadCipher:
    """Fernet encryption boundary for memory payloads."""

    def __init__(self, key: str | bytes | None = None) -> None:
        try:
            Fernet = importlib.import_module("cryptography.fernet").Fernet
        except ImportError as error:
            raise RuntimeError("cryptography is required for encrypted memory") from error
        configured = key or os.environ.get("MEMORY_GUARD_KEY")
        if not configured:
            raise RuntimeError("MEMORY_GUARD_KEY must be configured before storage access")
        self._fernet = Fernet(configured.encode() if isinstance(configured, str) else configured)

    def encrypt(self, value: Any) -> str:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        return self._fernet.encrypt(encoded).decode()

    def decrypt(self, token: str) -> Any:
        return json.loads(self._fernet.decrypt(token.encode()).decode())


class DatabaseManager:
    """SQLite repository for agent records and guard decisions."""

    def __init__(self, database_path: str | Path = "memory_guard.db", encryption_key: str | bytes | None = None) -> None:
        self.database_path = str(database_path)
        self.connection = sqlite3.connect(self.database_path)
        self.connection.row_factory = sqlite3.Row
        self.cipher = PayloadCipher(encryption_key)
        self.create_tables(agent=True, guard=True)

    def close(self) -> None:
        self.connection.close()

    def create_tables(self, agent: bool = False, guard: bool = False) -> bool:
        with self.connection:
            if agent:
                self.connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS agents (
                        agent_id TEXT PRIMARY KEY, agent_name TEXT NOT NULL,
                        agent_version TEXT NOT NULL, agent_author TEXT NOT NULL,
                        agent_description TEXT NOT NULL, session_id TEXT NOT NULL,
                        request_id TEXT NOT NULL, operation TEXT NOT NULL,
                        store TEXT NOT NULL, permissions TEXT NOT NULL,
                        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                    )
                    """
                )
            if guard:
                self.connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS guard_actions (
                        action_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
                        action TEXT NOT NULL, decision TEXT NOT NULL,
                        reasons TEXT NOT NULL, risk_score REAL NOT NULL,
                        confidence REAL NOT NULL, timestamp TEXT NOT NULL
                    )
                    """
                )
        return True

    def insert_data(self, table_name: str, data: dict[str, Any]) -> dict[str, Any]:
        table = self._normalize_table(table_name)
        if not data:
            raise ValueError("data cannot be empty")
        allowed = self._table_columns(table)
        values = {key: value for key, value in data.items() if key in allowed}
        missing = self._required_columns(table) - values.keys()
        if missing:
            raise ValueError(f"Missing required fields for {table}: {sorted(missing)}")
        columns = list(values)
        placeholders = ", ".join("?" for _ in columns)
        with self.connection:
            self.connection.execute(
                f"INSERT OR REPLACE INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",
                tuple(self._serialize(value) for value in values.values()),
            )
        return data

    def query_data(self, table_name: str, record_id: str) -> Optional[dict[str, Any]]:
        table = self._normalize_table(table_name)
        key = "agent_id" if table == "agents" else "action_id"
        row = self.connection.execute(
            f"SELECT * FROM {table} WHERE {key} = ?", (str(record_id),)
        ).fetchone()
        return dict(row) if row else None

    def delete_data(self, table_name: str, record_id: str) -> bool:
        table = self._normalize_table(table_name)
        key = "agent_id" if table == "agents" else "action_id"
        with self.connection:
            cursor = self.connection.execute(
                f"DELETE FROM {table} WHERE {key} = ?", (str(record_id),)
            )
        return cursor.rowcount > 0

    def _normalize_table(self, table_name: str) -> str:
        if table_name.lower() not in {"agent", "guard"}:
            raise ValueError("table_name must be Agent or Guard")
        return "agentsOperations" if table_name.lower() == "agent" else "guard_actions"

    def _table_columns(self, table: str) -> set[str]:
        return {row[1] for row in self.connection.execute(f"PRAGMA table_info({table})")}

    def _required_columns(self, table: str) -> set[str]:
        return {row[1] for row in self.connection.execute(f"PRAGMA table_info({table})") if row[3] and row[5] == 0}

    @staticmethod
    def _serialize(value: Any) -> Any:
        return json.dumps(value) if isinstance(value, (list, tuple, dict)) else value


class AgentDB:
    """Authorize and persist memory operations for one agent request."""

    def __init__(self, request: Optional[AgentRequest] = None, reasons: str = "", dbmanager: Optional[DatabaseManager] = None, provider: str = "generic", cyber_ai: Optional[CyberAI] = None, backend: Optional[ApplicationManagedBackend] = None) -> None:
        self.request = request
        self.reasons = reasons
        self.dbmanager = dbmanager or DatabaseManager()
        self.provider = provider
        self.cyber_ai = cyber_ai
        self.backend = backend

    def _metadata(self) -> dict[str, Any]:
        if self.request is None:
            return {}
        return {field: getattr(self.request, field) for field in (
            "agent_id", "agent_name", "agent_version", "agent_author",
            "agent_description", "tenant_id", "session_id", "request_id", "operation", "store"
        )} | {"permissions": list(self.request.permissions)}

    def _authorize(self, operation: str) -> GuardDecision:
        if self.request is None:
            return GuardDecision(Decision.QUARANTINE, 1.0, ("missing_request",), "pre")
        metadata = self._metadata()
        payload = self.request.data if self.request.data is not None else metadata
        guard = MemoryGuard(
            action=operation,
            source={"data": payload, "metadata": metadata},
            infos=metadata,
            cyber_ai=self.cyber_ai,
        )
        return guard.evaluate()

    def _agent_record(self) -> dict[str, Any]:
        if self.request is None:
            raise ValueError("An AgentRequest is required for this operation")
        now = datetime.now(timezone.utc).isoformat()
        return {**self._metadata(), "created_at": now, "updated_at": now}

    def read(self, id: Optional[str] = None) -> OperationReceipt:
        return self._run("read", id)

    def write(self, id: Optional[str] = None) -> OperationReceipt:
        return self._run("write", id, persist=True)

    def update(self, id: Optional[str] = None) -> OperationReceipt:
        return self._run("update", id, persist=True)

    def delete(self, id: Optional[str] = None) -> OperationReceipt:
        return self._run("delete", id, remove=True)

    def _run(self, operation: str, id: Optional[str], persist: bool = False, remove: bool = False) -> OperationReceipt:
        operation_id = str(uuid.uuid4())
        decision = self._authorize(operation)
        if decision.decision is not Decision.ALLOW:
            return OperationReceipt(operation_id, False)
        record_id = id or (self.request.agent_id if self.request else None)
        if not record_id:
            return OperationReceipt(operation_id, False)
        memory_id = self.request.memory_id or record_id
        if self.backend is not None:
            encrypted_request = replace(
                self.request,
                data=self.dbmanager.cipher.encrypt(self.request.data),
            )
            result = self.backend.execute(operation, encrypted_request, memory_id)
            if result is not None and operation in {"read", "search"}:
                try:
                    result = self.dbmanager.cipher.decrypt(result)
                except (TypeError, ValueError):
                    pass
        else:
            return OperationReceipt(operation_id, False)
        self._record_guard_action(operation, decision)
        return OperationReceipt(operation_id, True, result)

    @staticmethod
    def _embedding(value: Any, dimensions: int = 32) -> list[float]:
        """Deterministic local embedding fallback; replaceable by a model adapter."""
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True).encode()
        digest = hashlib.sha256(raw).digest()
        return [((digest[index % len(digest)] / 255.0) * 2.0) - 1.0 for index in range(dimensions)]

    def _record_guard_action(self, operation: str, decision: GuardDecision) -> None:
        if self.request is None:
            return
        self.dbmanager.insert_data("Guard", {
            "action_id": str(uuid.uuid4()), "agent_id": self.request.agent_id,
            "action": operation, "decision": decision.decision.value, "reasons": ",".join(decision.reason_codes) or self.reasons,
            "risk_score": decision.risk_score,
            "confidence": 1.0, "timestamp": datetime.now(timezone.utc).isoformat(),
        })


class MemoryAdapterInterface(ABC):
    """Common CRUD contract for every memory backend adapter."""

    @abstractmethod
    def read(self, request: AgentRequest, reasons: str = "") -> str: ...

    @abstractmethod
    def write(self, request: AgentRequest, reasons: str = "") -> str: ...

    @abstractmethod
    def update(self, request: AgentRequest, reasons: str = "") -> str: ...

    @abstractmethod
    def delete(self, request: AgentRequest, reasons: str = "") -> str: ...


class MemoryAdapterMixin:
    backend_name = "generic"
    backend_kind = "memory"
    capabilities = frozenset({"read", "write", "update", "delete"})

    def __init__(self, dbmanager: Optional[DatabaseManager] = None, **backend_config: Any) -> None:
        self.auth = "quarantine"
        self.backend_config = dict(backend_config)
        encryption_key = self.backend_config.pop("encryption_key", None)
        self.cyber_ai = self.backend_config.pop("cyber_ai", None)
        self.backend = self.backend_config.pop("backend", None)
        managed_db = dbmanager or DatabaseManager(encryption_key=encryption_key)
        self.agent_db = AgentDB(dbmanager=managed_db, cyber_ai=self.cyber_ai, backend=self.backend)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.backend_config.get("provider", self.backend_name),
            "kind": self.backend_kind,
            "capabilities": sorted(self.capabilities),
            "configuration": {
                key: value for key, value in self.backend_config.items()
                if key not in {"api_key", "access_key", "secret_key", "password", "token", "encryption_key"}
            },
        }

    def _dispatch(self, request: AgentRequest, reasons: str, operation: str) -> OperationReceipt:
        if request is None:
            raise ValueError("request is required")
        provider = self.backend_config.get("provider", "generic")
        self.agent_db = AgentDB(
            request=request,
            reasons=reasons,
            dbmanager=self.agent_db.dbmanager,
            provider=provider,
            cyber_ai=self.cyber_ai,
            backend=self.backend,
        )
        receipt = getattr(self.agent_db, operation)(id=request.agent_id)
        self.auth = "completed" if receipt.completed else "rejected"
        return receipt


class CRUDAdapter(MemoryAdapterInterface, MemoryAdapterMixin):
    def __init__(self, dbmanager: Optional[DatabaseManager] = None, **backend_config: Any) -> None:
        MemoryAdapterMixin.__init__(self, dbmanager, **backend_config)

    def read(self, request: AgentRequest, reasons: str = "") -> str:
        return self._dispatch(request, reasons, "read")

    def write(self, request: AgentRequest, reasons: str = "") -> str:
        return self._dispatch(request, reasons, "write")

    def update(self, request: AgentRequest, reasons: str = "") -> str:
        return self._dispatch(request, reasons, "update")

    def delete(self, request: AgentRequest, reasons: str = "") -> str:
        return self._dispatch(request, reasons, "delete")


class VectorAdapter(CRUDAdapter):
    backend_kind = "vector"

    def search(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def insert(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class RelationalAdapter(CRUDAdapter):
    backend_kind = "relational"

    execute_read = CRUDAdapter.read
    execute_write = CRUDAdapter.write
    execute_update = CRUDAdapter.update
    execute_delete = CRUDAdapter.delete


class DocumentMemoryAdapter(CRUDAdapter):
    backend_kind = "document"

    def find_doc(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def insert_doc(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class KeyValueMemoryAdapter(CRUDAdapter):
    backend_kind = "key_value"

    def get_val(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def set_val(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class GraphAdapter(CRUDAdapter):
    backend_kind = "graph"

    def query(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def create_nodeAndedge(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class SearchEngineAdapter(CRUDAdapter):
    backend_kind = "search"

    def search_index(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def index(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class ObjectStorageAdapter(CRUDAdapter):
    backend_kind = "object_storage"

    def get_obj(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def put_obj(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class FileSysAdapter(CRUDAdapter):
    backend_kind = "file"

    def read_file(self, request: AgentRequest, reasons: str = "") -> str: return self.read(request, reasons)
    def write_file(self, request: AgentRequest, reasons: str = "") -> str: return self.write(request, reasons)


class QDRANT(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("qdrant", config)
        collection = config.pop("collection", "memory")
        super().__init__(dbmanager, provider="qdrant", collection=collection, backend=QdrantBackend(collection, config.pop("url", None), config.pop("api_key", None)), **config)

class PINECONE(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("pinecone", config)
        index = config.pop("index", "memory")
        super().__init__(dbmanager, provider="pinecone", index=index, backend=PineconeBackend(index, config.pop("namespace", "default"), config.pop("api_key", None)), **config)

class WEAVIATE(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("weaviate", config)
        collection = config.pop("class_name", "Memory")
        super().__init__(dbmanager, provider="weaviate", class_name=collection, backend=WeaviateBackend(collection, config.pop("url", os.environ.get("WEAVIATE_URL")), config.pop("api_key", os.environ.get("WEAVIATE_API_KEY"))), **config)

class MILVUS(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("milvus", config)
        collection = config.pop("collection", "memory")
        super().__init__(dbmanager, provider="milvus", collection=collection, backend=MilvusBackend(collection, config.pop("uri", os.environ.get("MILVUS_URL")), config.pop("token", os.environ.get("MILVUS_TOKEN"))), **config)

class CHROMA(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("chroma", config)
        collection = config.pop("collection", "memory")
        super().__init__(dbmanager, provider="chroma", collection=collection, backend=ChromaBackend(collection, config.pop("host", os.environ.get("CHROMA_HOST")), int(config.pop("port", os.environ.get("CHROMA_PORT", "8000")))), **config)

class FAISS(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        index_path = config.pop("index_path", "memory.index")
        super().__init__(dbmanager, provider="faiss", index_path=index_path, backend=FaissBackend(index_path, int(config.pop("dimensions", 32))), **config)

class PGVECTOR(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("pgvector", config)
        table = config.pop("table", "agent_memory")
        schema = config.pop("schema", None)
        url = config.pop("url", os.environ.get("PGVECTOR_URL") or os.environ.get("POSTGRESQL_URL"))
        if not url:
            raise SDKUnavailable("PGVECTOR_URL or POSTGRESQL_URL is required")
        super().__init__(dbmanager, provider="pgvector", table=table,
                         backend=SQLBackend(url, table=table, schema=schema), **config)

class VESPA(VectorAdapter):
    def __init__(self, dbmanager=None, **config):
        url = config.pop("url", os.environ.get("VESPA_URL"))
        schema = config.pop("schema", "memory")
        namespace = config.pop("namespace", "aso")
        backend = VespaBackend(url, schema=schema, namespace=namespace,
                               timeout=float(config.pop("timeout", 10)),
                               api_key=config.pop("api_key", os.environ.get("VESPA_API_KEY")))
        super().__init__(dbmanager, provider="vespa", schema=schema, backend=backend, **config)

class POSTGRESQL(RelationalAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("postgresql", config)
        schema = config.pop("schema", "public")
        table = config.pop("table", "agent_memory")
        url = config.pop("url", os.environ.get("POSTGRESQL_URL"))
        super().__init__(dbmanager, provider="postgresql", schema=schema,
                         backend=SQLBackend(url, table=table, schema=schema), **config)

class ORACLE(RelationalAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("oracle", config)
        schema = config.pop("schema", "MEMORY")
        table = config.pop("table", "agent_memory")
        url = config.pop("url", os.environ.get("ORACLE_URL"))
        super().__init__(dbmanager, provider="oracle", schema=schema,
                         backend=SQLBackend(url, table=table, schema=schema), **config)

class SQLITE(RelationalAdapter):
    def __init__(self, dbmanager=None, **config):
        database_path = config.pop("database_path", "agent_memory.db")
        super().__init__(dbmanager, provider="sqlite", table=config.pop("table", "memory"), backend=SQLiteBackend(database_path), **config)

class SQLSERVER(RelationalAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("sqlserver", config)
        schema = config.pop("schema", "dbo")
        table = config.pop("table", "agent_memory")
        url = config.pop("url", os.environ.get("SQLSERVER_URL"))
        super().__init__(dbmanager, provider="sqlserver", schema=schema,
                         backend=SQLBackend(url, table=table, schema=schema), **config)

class MARIADB(RelationalAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("mariadb", config)
        table = config.pop("table", "agent_memory")
        schema = config.pop("schema", None)
        url = config.pop("url", os.environ.get("MARIADB_URL"))
        super().__init__(dbmanager, provider="mariadb", table=table,
                         backend=SQLBackend(url, table=table, schema=schema), **config)

class MONGODB(DocumentMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("mongodb", config)
        collection = config.pop("collection", "memory")
        super().__init__(dbmanager, provider="mongodb", collection=collection, backend=MongoBackend(config.pop("database", "memory"), collection, config.pop("uri", None)), **config)

class COUCHDB(DocumentMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("couchdb", config)
        database = config.pop("database", "memory")
        super().__init__(dbmanager, provider="couchdb", database=database, backend=CouchDBBackend(database, config.pop("url", os.environ.get("COUCHDB_URL")), config.pop("username", os.environ.get("COUCHDB_USERNAME")), config.pop("password", os.environ.get("COUCHDB_PASSWORD"))), **config)

class FIRESTORE(DocumentMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        collection = config.pop("collection", "memory")
        super().__init__(dbmanager, provider="firestore", collection=collection, backend=FirestoreBackend(collection), **config)

class DYNAMODB(DocumentMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("dynamodb", config)
        table = config.pop("table", "memory")
        super().__init__(dbmanager, provider="dynamodb", table=table, backend=DynamoDBBackend(table, config.pop("region", None)), **config)

class REDIS(KeyValueMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("redis", config)
        namespace = config.pop("namespace", "memory")
        super().__init__(dbmanager, provider="redis", namespace=namespace, backend=RedisBackend(namespace, config.pop("url", None)), **config)

class VALKEY(KeyValueMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        namespace = config.pop("namespace", "memory")
        super().__init__(dbmanager, provider="valkey", namespace=namespace, backend=ValkeyBackend(namespace, config.pop("url", os.environ.get("VALKEY_URL"))), **config)

class MEMECACHED(KeyValueMemoryAdapter):
    def __init__(self, dbmanager=None, **config):
        super().__init__(dbmanager, provider="memcached", namespace=config.pop("namespace", "memory"), backend=MemcachedBackend(config.pop("host", os.environ.get("MEMCACHED_HOST")), int(config.pop("port", os.environ.get("MEMCACHED_PORT", "11211")))), **config)


MEMCACHED = MEMECACHED

class NEO4J(GraphAdapter):
    def __init__(self, dbmanager=None, **config):
        super().__init__(dbmanager, provider="neo4j", graph=config.pop("graph", "memory"), backend=Neo4jBackend(config.pop("url", os.environ.get("NEO4J_URI")), config.pop("username", os.environ.get("NEO4J_USERNAME")), config.pop("password", os.environ.get("NEO4J_PASSWORD"))), **config)

class AMAZONE_NEPTURE(GraphAdapter):
    def __init__(self, dbmanager=None, **config):
        super().__init__(dbmanager, provider="amazon_neptune", graph=config.pop("graph", "memory"), backend=NeptuneBackend(config.pop("url", os.environ.get("NEPTUNE_URI")), config.pop("username", os.environ.get("NEPTUNE_USERNAME")), config.pop("password", os.environ.get("NEPTUNE_PASSWORD"))), **config)

class ARANGO_DB(GraphAdapter):
    def __init__(self, dbmanager=None, **config):
        super().__init__(dbmanager, provider="arangodb", graph=config.pop("graph", "memory"), backend=ArangoBackend(config.pop("url", os.environ.get("ARANGO_URL")), config.pop("database", "memory"), config.pop("username", os.environ.get("ARANGO_USERNAME")), config.pop("password", os.environ.get("ARANGO_PASSWORD"))), **config)

class TIGER_GRAPH(GraphAdapter):
    def __init__(self, dbmanager=None, **config):
        graph = config.pop("graph", "memory")
        vertex_type = config.pop("vertex_type", "Memory")
        backend = TigerGraphBackend(
            config.pop("url", os.environ.get("TIGERGRAPH_URL")),
            config.pop("username", os.environ.get("TIGERGRAPH_USERNAME")),
            config.pop("password", os.environ.get("TIGERGRAPH_PASSWORD")),
            graph,
            vertex_type,
        )
        super().__init__(dbmanager, provider="tigergraph", graph=graph, backend=backend, **config)

class AMAZON_NEPTUNE(GraphAdapter):
    def __init__(self, dbmanager=None, **config):
        graph = config.pop("graph", "memory")
        backend = NeptuneBackend(
            config.pop("url", os.environ.get("NEPTUNE_URI")),
            config.pop("username", os.environ.get("NEPTUNE_USERNAME")),
            config.pop("password", os.environ.get("NEPTUNE_PASSWORD")),
        )
        super().__init__(dbmanager, provider="amazon_neptune", graph=graph, backend=backend, **config)

class LANGRAPH(GraphAdapter):
    def __init__(self, dbmanager=None, **config):
        super().__init__(dbmanager, provider="langgraph", graph=config.pop("graph", "memory"), backend=LangGraphBackend(config.pop("graph_app", None)), **config)

class SOLR(SearchEngineAdapter):
    def __init__(self, dbmanager=None, **config):
        core = config.pop("core", "memory")
        super().__init__(dbmanager, provider="solr", core=core, backend=SolrBackend(config.pop("url", os.environ.get("SOLR_URL")), core), **config)

class OPENSEARCH(SearchEngineAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("opensearch", config)
        index = config.pop("index", "memory")
        super().__init__(dbmanager, provider="opensearch", index=index, backend=OpenSearchBackend(index, config.pop("url", os.environ.get("OPENSEARCH_URL")), config.pop("api_key", os.environ.get("OPENSEARCH_API_KEY"))), **config)

class ELASTICSEARCH(SearchEngineAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("elasticsearch", config)
        index = config.pop("index", "memory")
        super().__init__(dbmanager, provider="elasticsearch", index=index, backend=ElasticsearchBackend(index, config.pop("url", None), config.pop("api_key", None)), **config)

class AMAZON_S3(ObjectStorageAdapter):
    def __init__(self, dbmanager=None, **config):
        config = _managed_provider_config("amazon_s3", config)
        bucket = config.pop("bucket", "memory")
        super().__init__(dbmanager, provider="amazon_s3", bucket=bucket, backend=S3Backend(bucket, config.pop("prefix", "memory"), config.pop("region", None)), **config)

class GOOGLE_CLOUD_STORAGE(ObjectStorageAdapter):
    def __init__(self, dbmanager=None, **config):
        bucket = config.pop("bucket", "memory")
        super().__init__(dbmanager, provider="google_cloud_storage", bucket=bucket, backend=GCSBackend(bucket, config.pop("prefix", "memory")), **config)

class AZURE_BLOB_STORAGE(ObjectStorageAdapter):
    def __init__(self, dbmanager=None, **config):
        container = config.pop("container", "memory")
        super().__init__(dbmanager, provider="azure_blob_storage", container=container, backend=AzureBlobBackend(config.pop("account_url", os.environ.get("AZURE_STORAGE_ACCOUNT_URL")), container, config.pop("credential", os.environ.get("AZURE_STORAGE_CREDENTIAL"))), **config)

class JSON(FileSysAdapter):
    def __init__(self, dbmanager=None, **config):
        path = config.pop("path", "memory.json")
        super().__init__(dbmanager, provider="json", path=path, backend=FileBackend(path, "json"), **config)

class YAML(FileSysAdapter):
    def __init__(self, dbmanager=None, **config):
        path = config.pop("path", "memory.yaml")
        super().__init__(dbmanager, provider="yaml", path=path, backend=FileBackend(path, "yaml"), **config)

class CSV(FileSysAdapter):
    def __init__(self, dbmanager=None, **config):
        path = config.pop("path", "memory.csv")
        super().__init__(dbmanager, provider="csv", path=path, backend=FileBackend(path, "csv"), **config)

class TXT(FileSysAdapter):
    def __init__(self, dbmanager=None, **config):
        path = config.pop("path", "memory.txt")
        super().__init__(dbmanager, provider="txt", path=path, backend=FileBackend(path, "txt"), **config)

class LOCALFILES(FileSysAdapter):
    def __init__(self, dbmanager=None, **config):
        path = config.pop("path", "memory_files")
        super().__init__(dbmanager, provider="local_files", path=path, backend=FileBackend(path, "txt"), **config)


class StoreRegistry:
    """Application-owned mapping from logical stores to hidden adapters."""

    def __init__(self) -> None:
        self._stores: dict[str, StoreConfig] = {}

    def register(self, config: StoreConfig) -> None:
        if config.store_id in self._stores:
            raise ValueError(f"store already registered: {config.store_id}")
        self._stores[config.store_id] = config

    def resolve(self, store_id: str) -> StoreConfig:
        try:
            return self._stores[store_id]
        except KeyError as error:
            raise PermissionError("unknown memory store") from error

    def list_store_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._stores))


class AuditLog:
    """Append-only in-process audit sink; agents receive no mutable log handle."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self._events.append(event)

    def snapshot(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)


class QuarantineStore:
    """Private holding area for suspicious data; never exposed through agent results."""

    def __init__(self) -> None:
        self._items: dict[str, dict[str, Any]] = {}

    def put(self, request_id: str, payload: Any, reason_codes: tuple[str, ...]) -> str:
        quarantine_id = str(uuid.uuid4())
        self._items[quarantine_id] = {
            "request_id": request_id,
            "payload": payload,
            "reason_codes": tuple(reason_codes),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        return quarantine_id

    def snapshot(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(item) for item in self._items.values())


@dataclass(frozen=True)
class AccessResult:
    request_id: str
    decision: Decision
    data: Any = None
    reason_codes: tuple[str, ...] = ()
    operation_id: str | None = None
