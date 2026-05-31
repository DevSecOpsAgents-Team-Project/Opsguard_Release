"""
Chroma persistent DB(chroma.sqlite3) 메타데이터 보정.

chromadb 최신 버전은 collections.config_json_str / schema_str 에 `_type` 필드를 요구한다.
구버전/부분 마이그레이션 DB에서는 KeyError: '_type' 가 발생할 수 있어,
모든 컬렉션 행에 대해 idempotent 하게 보정한다.
"""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Any, Dict, Optional


def _fix_all_types(obj: Any) -> None:
    """embedding_function 등에서 type → _type 치환."""
    if isinstance(obj, dict):
        if "type" in obj and "_type" not in obj and obj.get("type") in ("known", "unknown"):
            obj["_type"] = obj.pop("type")
        elif "type" in obj and "name" in obj and "_type" not in obj:
            obj["_type"] = obj.pop("type")
        for v in list(obj.values()):
            _fix_all_types(v)
    elif isinstance(obj, list):
        for v in obj:
            _fix_all_types(v)


def _normalize_schema_dict(schema: Dict[str, Any]) -> Dict[str, Any]:
    if "_type" not in schema:
        try:
            from chromadb.api.configuration import CollectionConfigurationInternal

            schema = CollectionConfigurationInternal().to_json()
        except Exception:
            schema = {"_type": "CollectionConfigurationInternal"}
    _fix_all_types(schema)
    return schema


def _normalize_config_str(config_raw: Optional[str]) -> str:
    try:
        from chromadb.api.configuration import CollectionConfigurationInternal

        default_str = CollectionConfigurationInternal().to_json_str()
    except Exception:
        default_str = json.dumps({"_type": "CollectionConfigurationInternal"})

    if not config_raw or not str(config_raw).strip():
        return default_str
    try:
        cfg = json.loads(config_raw)
    except json.JSONDecodeError:
        return default_str

    if isinstance(cfg, dict) and cfg.get("_type") == "CollectionConfigurationInternal":
        return config_raw

    if not isinstance(cfg, dict) or len(cfg) == 0 or "_type" not in cfg:
        return default_str

    return config_raw


def repair_chroma_sqlite(chroma_dir: str) -> bool:
    """
    chroma.sqlite3 의 모든 collections 행을 보정한다.

    Returns:
        chroma.sqlite3 파일이 있어 처리 시도했으면 True, 없으면 False.
    """
    path = os.path.join(os.path.expanduser(chroma_dir), "chroma.sqlite3")
    if not os.path.isfile(path):
        return False

    conn = sqlite3.connect(path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT name, schema_str, config_json_str FROM collections")
        rows = cur.fetchall()
        for name, schema_str, config_json_str in rows:
            try:
                schema = json.loads(schema_str) if schema_str else {}
            except json.JSONDecodeError:
                schema = {}
            if not isinstance(schema, dict):
                schema = {}
            schema = _normalize_schema_dict(schema)
            new_schema = json.dumps(schema)
            new_config = _normalize_config_str(config_json_str)
            cur.execute(
                "UPDATE collections SET schema_str=?, config_json_str=? WHERE name=?",
                (new_schema, new_config, name),
            )
        conn.commit()
    finally:
        conn.close()
    return True
