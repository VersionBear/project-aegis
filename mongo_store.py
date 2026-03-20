from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv
from pymongo import MongoClient


DEFAULT_DATABASE_NAME = "project_aegis"
DEFAULT_COLLECTION_NAME = "settings"


class MongoSettingsStore:
    def __init__(self, uri: str, *, database_name: str = DEFAULT_DATABASE_NAME, collection_name: str = DEFAULT_COLLECTION_NAME) -> None:
        self.client = MongoClient(uri)
        self.collection = self.client[database_name][collection_name]

    def load_runtime_config(self) -> dict[str, Any]:
        return self._load_document("runtime_config")

    def save_runtime_config(self, payload: dict[str, Any]) -> None:
        self.collection.update_one({"_id": "runtime_config"}, {"$set": payload}, upsert=True)

    def load_id_set(self, key: str) -> set[int]:
        values = self._load_document(key).get("values", [])
        return {int(value) for value in values if _looks_like_int(value)}

    def save_id_set(self, key: str, values: set[int]) -> None:
        self.collection.update_one(
            {"_id": key},
            {"$set": {"values": sorted(values)}},
            upsert=True,
        )

    def load_domain_set(self, key: str) -> set[str]:
        from utils import normalize_domain

        values = self._load_document(key).get("values", [])
        return {
            normalized
            for value in values
            if isinstance(value, str)
            if (normalized := normalize_domain(value))
        }

    def save_domain_set(self, key: str, values: set[str]) -> None:
        self.collection.update_one(
            {"_id": key},
            {"$set": {"values": sorted(values)}},
            upsert=True,
        )

    def close(self) -> None:
        self.client.close()

    def _load_document(self, key: str) -> dict[str, Any]:
        document = self.collection.find_one({"_id": key}) or {}
        return document if isinstance(document, dict) else {}


class InMemorySettingsStore:
    def __init__(self) -> None:
        self.documents: dict[str, dict[str, Any]] = {}

    def load_runtime_config(self) -> dict[str, Any]:
        return dict(self.documents.get("runtime_config", {}))

    def save_runtime_config(self, payload: dict[str, Any]) -> None:
        self.documents["runtime_config"] = dict(payload)

    def load_id_set(self, key: str) -> set[int]:
        values = self.documents.get(key, {}).get("values", [])
        return {int(value) for value in values if _looks_like_int(value)}

    def save_id_set(self, key: str, values: set[int]) -> None:
        self.documents[key] = {"values": sorted(values)}

    def load_domain_set(self, key: str) -> set[str]:
        from utils import normalize_domain

        values = self.documents.get(key, {}).get("values", [])
        return {
            normalized
            for value in values
            if isinstance(value, str)
            if (normalized := normalize_domain(value))
        }

    def save_domain_set(self, key: str, values: set[str]) -> None:
        self.documents[key] = {"values": sorted(values)}

    def close(self) -> None:
        return


def get_default_store():
    load_dotenv()
    uri = os.getenv("MONGODB_URI", "").strip()
    if not uri:
        raise RuntimeError("MONGODB_URI is required")
    database_name = os.getenv("MONGODB_DB_NAME", DEFAULT_DATABASE_NAME).strip() or DEFAULT_DATABASE_NAME
    collection_name = os.getenv("MONGODB_COLLECTION_NAME", DEFAULT_COLLECTION_NAME).strip() or DEFAULT_COLLECTION_NAME
    return MongoSettingsStore(uri, database_name=database_name, collection_name=collection_name)


def _looks_like_int(value: Any) -> bool:
    try:
        int(value)
    except (TypeError, ValueError):
        return False
    return True
