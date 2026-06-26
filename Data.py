#!/usr/bin/env python3
# Copyright (C) 2026 花吹雪又一年
#
# This file is part of Roco-Kingdom-Protocol-Parser (RKPP).
# Licensed under the GNU Affero General Public License v3.0 only (AGPL-3.0-only).
# You must retain the author attribution, this notice, the LICENSE file,
# and the NOTICE file in redistributions and derivative works.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the LICENSE
# file for more details.

"""RKPP runtime data access.

Release builds use ``rkpp_data.sqlite`` at the project root. Payload columns are
MessagePack blobs so hot lookups do not need to parse the old multi-file JSON
bundle. The old ``Data/`` JSON layout is kept as a maintenance fallback.
"""
from __future__ import annotations

import csv
import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable

import msgpack

logger = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DB = SCRIPT_DIR / "rkpp_data.sqlite"
DATA_DIR = SCRIPT_DIR / "Data"

ATTR_CSV = DATA_DIR / "Attr.csv"
PET_CSV = DATA_DIR / "Pet.csv"
SKILL_CSV = DATA_DIR / "Skill.csv"

ATTR_MAP_JSON = DATA_DIR / "attr_map.json"
SKILL_MAP_JSON = DATA_DIR / "skill_map.json"
BUFF_MAP_JSON = DATA_DIR / "buff_map.json"
BUFFBASE_MAP_JSON = DATA_DIR / "buffbase_map.json"
PET_MAP_JSON = DATA_DIR / "pet_map.json"
MONSTER_MAP_JSON = DATA_DIR / "monster_map.json"
PET_SKILL_MAP_JSON = DATA_DIR / "pet_skill_map.json"
MONSTER_SKILLBANK_MAP_JSON = DATA_DIR / "monster_skillbank_map.json"
SPECIAL_MOVE_MAP_JSON = DATA_DIR / "special_move_map.json"
OPCODE_PB_MAP_JSON = DATA_DIR / "opcode_pb_map.json"
PB_MESSAGE_INDEX_JSON = DATA_DIR / "pb_message_index.json"
OPCODE_JSON = DATA_DIR / "opcode.json"
PROTO_SCHEMA_JSON = DATA_DIR / "proto_schema.json"
DATA_MANIFEST_JSON = DATA_DIR / "data_manifest.json"

_JSON_PATHS: dict[str, Path] = {
    "attr_meta": ATTR_MAP_JSON,
    "skill_meta": SKILL_MAP_JSON,
    "buff_meta": BUFF_MAP_JSON,
    "buffbase_meta": BUFFBASE_MAP_JSON,
    "pet_meta": PET_MAP_JSON,
    "monster_meta": MONSTER_MAP_JSON,
    "pet_skill_meta": PET_SKILL_MAP_JSON,
    "monster_skillbank_meta": MONSTER_SKILLBANK_MAP_JSON,
    "special_move_meta": SPECIAL_MOVE_MAP_JSON,
    "opcode_pb_meta": OPCODE_PB_MAP_JSON,
    "pb_message_meta": PB_MESSAGE_INDEX_JSON,
    "opcode_map": OPCODE_JSON,
    "proto_schema": PROTO_SCHEMA_JSON,
    "manifest": DATA_MANIFEST_JSON,
}

_ENTITY_KIND_BY_BUNDLE_KEY = {
    "attr_meta": "attr",
    "skill_meta": "skill",
    "buff_meta": "buff",
    "buffbase_meta": "buffbase",
    "pet_meta": "pet",
    "monster_meta": "monster",
    "pet_skill_meta": "pet_skill",
    "monster_skillbank_meta": "monster_skillbank",
    "special_move_meta": "special_move",
}


def _safe_int(text: str | None) -> int | None:
    if text is None:
        return None
    s = text.strip()
    try:
        return int(s, 10) if s else None
    except ValueError:
        return None


def _normalize_skill_id(value: int | None) -> int | None:
    if value is None or value <= 0:
        return None
    return value // 100 if value >= 100_000 and value % 100 == 0 else value


def _read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        rows: list[dict[str, str]] = []
        for row in reader:
            norm = {str(k).strip(): (v or "").strip() for k, v in row.items() if k is not None}
            if any(norm.values()):
                rows.append(norm)
        return rows


def _build_id_name_map(rows: list[dict[str, str]], *, id_field: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for row in rows:
        eid = _safe_int(row.get(id_field))
        name = (row.get("name") or "").strip()
        if eid is not None and name:
            out[eid] = name
    return out


def _read_json_dict(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning("Failed to load JSON data bundle %s: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _int_keyed_meta(raw: dict[str, Any]) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for key, value in raw.items():
        try:
            ikey = int(key)
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict):
            out[ikey] = value
    return out


def _name_map_from_meta(meta: dict[int, dict[str, Any]]) -> dict[int, str]:
    out: dict[int, str] = {}
    for key, value in meta.items():
        name = value.get("name")
        if isinstance(name, str) and name:
            out[key] = name
    return out


_json_cache: dict[str, Any] | None = None
_maps_cache: dict[str, dict[int, str]] | None = None
_sqlite_conn: sqlite3.Connection | None = None
_sqlite_available: bool | None = None
_lock = threading.RLock()

_MetaNormalizer = Callable[[int | None], int | None]


def _unpack_payload(payload: bytes | memoryview | None) -> Any:
    if payload is None:
        return None
    return msgpack.unpackb(bytes(payload), raw=False, strict_map_key=False)


def _connect_sqlite() -> sqlite3.Connection | None:
    global _sqlite_conn, _sqlite_available
    if _sqlite_available is False:
        return None
    if not DATA_DB.exists():
        _sqlite_available = False
        return None
    if _sqlite_conn is None:
        try:
            uri = f"file:{DATA_DB.as_posix()}?mode=ro"
            _sqlite_conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
            _sqlite_conn.row_factory = sqlite3.Row
            _sqlite_available = True
        except sqlite3.Error as exc:
            logger.warning("Failed to open sqlite data bundle %s: %s", DATA_DB, exc)
            _sqlite_available = False
            _sqlite_conn = None
    return _sqlite_conn


def _sqlite_payload(sql: str, params: tuple[Any, ...]) -> Any:
    conn = _connect_sqlite()
    if conn is None:
        return None
    try:
        row = conn.execute(sql, params).fetchone()
    except sqlite3.Error as exc:
        logger.warning("Failed sqlite data query: %s", exc)
        return None
    if row is None:
        return None
    return _unpack_payload(row["payload_msgpack"])


def _sqlite_int_payload(table: str, id_column: str, value: int | None) -> dict[str, Any] | None:
    if value is None:
        return None
    payload = _sqlite_payload(f"SELECT payload_msgpack FROM {table} WHERE {id_column}=?", (int(value),))
    return payload if isinstance(payload, dict) else None


def _sqlite_entity(kind: str, value: int | None) -> dict[str, Any] | None:
    if value is None:
        return None
    payload = _sqlite_payload(
        "SELECT payload_msgpack FROM entity WHERE kind=? AND id=?",
        (kind, int(value)),
    )
    return payload if isinstance(payload, dict) else None


def _sqlite_all_entities(kind: str) -> dict[int, dict[str, Any]]:
    conn = _connect_sqlite()
    if conn is None:
        return {}
    out: dict[int, dict[str, Any]] = {}
    for row in conn.execute("SELECT id, payload_msgpack FROM entity WHERE kind=?", (kind,)):
        payload = _unpack_payload(row["payload_msgpack"])
        if isinstance(payload, dict):
            out[int(row["id"])] = payload
    return out


def _sqlite_name_map(kind: str) -> dict[int, str]:
    conn = _connect_sqlite()
    if conn is None:
        return {}
    out: dict[int, str] = {}
    for row in conn.execute("SELECT id, name FROM entity WHERE kind=? AND name IS NOT NULL", (kind,)):
        name = row["name"]
        if isinstance(name, str) and name:
            out[int(row["id"])] = name
    return out


def _sqlite_get_meta_value(key: str) -> dict[str, Any] | None:
    payload = _sqlite_payload("SELECT payload_msgpack FROM meta WHERE key=?", (key,))
    return payload if isinstance(payload, dict) else None


def _sqlite_get_kv(kind: str, key: str = "root") -> dict[str, Any] | None:
    payload = _sqlite_payload(
        "SELECT payload_msgpack FROM kv WHERE kind=? AND key=?",
        (kind, key),
    )
    return payload if isinstance(payload, dict) else None


def _sqlite_opcode_map() -> dict[str, dict[str, Any]]:
    conn = _connect_sqlite()
    if conn is None:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in conn.execute("SELECT opcode, payload_msgpack FROM opcode"):
        payload = _unpack_payload(row["payload_msgpack"])
        if isinstance(payload, dict):
            out[str(int(row["opcode"]))] = payload
    return out


def _sqlite_opcode_pb_map() -> dict[int, dict[str, Any]]:
    conn = _connect_sqlite()
    if conn is None:
        return {}
    out: dict[int, dict[str, Any]] = {}
    for row in conn.execute("SELECT opcode, payload_msgpack FROM opcode_pb"):
        payload = _unpack_payload(row["payload_msgpack"])
        if isinstance(payload, dict):
            out[int(row["opcode"])] = payload
    return out


def _sqlite_pb_message_map() -> dict[str, dict[str, Any]]:
    conn = _connect_sqlite()
    if conn is None:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in conn.execute("SELECT name, payload_msgpack FROM pb_message"):
        payload = _unpack_payload(row["payload_msgpack"])
        if isinstance(payload, dict):
            out[str(row["name"])] = payload
    return out


def has_sqlite_bundle() -> bool:
    return _connect_sqlite() is not None


def _load_json_bundle() -> dict[str, Any]:
    bundle: dict[str, Any] = {}
    for name, path in _JSON_PATHS.items():
        raw = _read_json_dict(path)
        if name in {"manifest", "pb_message_meta", "opcode_map", "proto_schema"}:
            bundle[name] = raw
        else:
            bundle[name] = _int_keyed_meta(raw)
    return bundle


def _load_sqlite_bundle() -> dict[str, Any]:
    bundle: dict[str, Any] = {
        "manifest": _sqlite_get_meta_value("manifest") or {},
        "pb_message_meta": _sqlite_pb_message_map(),
        "opcode_pb_meta": _sqlite_opcode_pb_map(),
        "opcode_map": _sqlite_opcode_map(),
        "proto_schema": _sqlite_get_kv("proto_schema") or {"messages": {}, "enums": {}},
    }
    for bundle_key, kind in _ENTITY_KIND_BY_BUNDLE_KEY.items():
        bundle[bundle_key] = _sqlite_all_entities(kind)
    return bundle


def get_bundle() -> dict[str, Any]:
    global _json_cache
    if _json_cache is not None:
        return _json_cache
    with _lock:
        if _json_cache is None:
            _json_cache = _load_sqlite_bundle() if has_sqlite_bundle() else _load_json_bundle()
        return _json_cache


def _load_all_maps() -> dict[str, dict[int, str]]:
    if has_sqlite_bundle():
        pet_map = _sqlite_name_map("pet")
        pet_map.update(_sqlite_name_map("monster"))
        return {
            "attr": _sqlite_name_map("attr"),
            "pet": pet_map,
            "skill": _sqlite_name_map("skill"),
        }

    bundle = get_bundle()
    csv_attr = _build_id_name_map(_read_rows(ATTR_CSV), id_field="attr_id")
    csv_pet = _build_id_name_map(_read_rows(PET_CSV), id_field="pet_id")
    csv_skill = _build_id_name_map(_read_rows(SKILL_CSV), id_field="skill_id")

    attr_map = dict(csv_attr)
    attr_map.update(_name_map_from_meta(bundle.get("attr_meta", {})))

    pet_map = dict(csv_pet)
    pet_map.update(_name_map_from_meta(bundle.get("pet_meta", {})))

    skill_map = dict(csv_skill)
    skill_map.update(_name_map_from_meta(bundle.get("skill_meta", {})))

    return {
        "attr": attr_map,
        "pet": pet_map,
        "skill": skill_map,
    }


def get_maps() -> dict[str, dict[int, str]]:
    """兼容旧接口：返回 attr / pet / skill 三张 id->name 映射表。"""
    global _maps_cache
    if _maps_cache is not None:
        return _maps_cache
    with _lock:
        if _maps_cache is None:
            _maps_cache = _load_all_maps()
        return _maps_cache


def _normalize_lookup_value(value: int | None, *, normalizer: _MetaNormalizer | None = None) -> int | None:
    if value is None:
        return None
    normalized = normalizer(value) if normalizer else value
    if normalized is None:
        return None
    return int(normalized)


def _get_bundle_meta(
    *bundle_keys: str,
    value: int | None,
    normalizer: _MetaNormalizer | None = None,
) -> dict[str, Any] | None:
    lookup_key = _normalize_lookup_value(value, normalizer=normalizer)
    if lookup_key is None:
        return None

    if has_sqlite_bundle():
        for bundle_key in bundle_keys:
            if bundle_key == "opcode_pb_meta":
                entry = _sqlite_int_payload("opcode_pb", "opcode", lookup_key)
            else:
                kind = _ENTITY_KIND_BY_BUNDLE_KEY.get(bundle_key)
                entry = _sqlite_entity(kind, lookup_key) if kind else None
            if isinstance(entry, dict):
                return entry
        return None

    bundle = get_bundle()
    for bundle_key in bundle_keys:
        entry = bundle.get(bundle_key, {}).get(lookup_key)
        if isinstance(entry, dict):
            return entry
    return None


def _get_meta_name(meta: dict[str, Any] | None) -> str | None:
    if meta and isinstance(meta.get("name"), str):
        return meta["name"]
    return None


def _get_name_from_meta_or_map(
    *bundle_keys: str,
    value: int | None,
    map_name: str | None = None,
    normalizer: _MetaNormalizer | None = None,
) -> str | None:
    meta = _get_bundle_meta(*bundle_keys, value=value, normalizer=normalizer)
    name = _get_meta_name(meta)
    if name:
        return name
    if map_name is None:
        return None
    lookup_key = _normalize_lookup_value(value, normalizer=normalizer)
    if lookup_key is None:
        return None
    return get_maps()[map_name].get(lookup_key)


def get_attr_meta(attr_id: int | None) -> dict[str, Any] | None:
    return _get_bundle_meta("attr_meta", value=attr_id)


def get_attr_name(attr_id: int | None) -> str | None:
    return _get_name_from_meta_or_map("attr_meta", value=attr_id, map_name="attr")


def get_skill_meta(skill_id: int | None) -> dict[str, Any] | None:
    return _get_bundle_meta("skill_meta", value=skill_id) or _get_bundle_meta(
        "skill_meta",
        value=skill_id,
        normalizer=_normalize_skill_id,
    )


def get_skill_name(skill_id: int | None) -> str | None:
    return _get_name_from_meta_or_map(
        "skill_meta",
        value=skill_id,
        map_name="skill",
    ) or _get_name_from_meta_or_map(
        "skill_meta",
        value=skill_id,
        map_name="skill",
        normalizer=_normalize_skill_id,
    )


def get_buff_meta(buff_id: int | None) -> dict[str, Any] | None:
    return _get_bundle_meta("buff_meta", value=buff_id)


def get_buffbase_meta(buffbase_id: int | None) -> dict[str, Any] | None:
    return _get_bundle_meta("buffbase_meta", value=buffbase_id)


def get_pet_meta(pet_id: int | None) -> dict[str, Any] | None:
    return _get_bundle_meta("pet_meta", "monster_meta", value=pet_id)


def get_pet_name(pet_id: int | None) -> str | None:
    return _get_name_from_meta_or_map("pet_meta", "monster_meta", value=pet_id, map_name="pet")


def get_monster_meta(monster_id: int | None) -> dict[str, Any] | None:
    return _get_bundle_meta("monster_meta", value=monster_id)


def get_pet_skill_meta(base_id: int | None) -> dict[str, Any] | None:
    return _get_bundle_meta("pet_skill_meta", value=base_id)


def get_monster_skillbank_meta(bank_id: int | None) -> dict[str, Any] | None:
    return _get_bundle_meta("monster_skillbank_meta", value=bank_id)


def get_special_move_meta(move_id: int | None) -> dict[str, Any] | None:
    return _get_bundle_meta("special_move_meta", value=move_id)


def get_opcode_pb_meta(opcode: int | None) -> dict[str, Any] | None:
    return _get_bundle_meta("opcode_pb_meta", value=opcode)


def get_pb_message_meta(name: str | None) -> dict[str, Any] | None:
    if not name:
        return None
    if has_sqlite_bundle():
        payload = _sqlite_payload(
            "SELECT payload_msgpack FROM pb_message WHERE name=?",
            (name,),
        )
        return payload if isinstance(payload, dict) else None
    value = get_bundle().get("pb_message_meta", {}).get(name)
    return value if isinstance(value, dict) else None


def get_manifest() -> dict[str, Any]:
    if has_sqlite_bundle():
        return _sqlite_get_meta_value("manifest") or {}
    manifest = get_bundle().get("manifest", {})
    return manifest if isinstance(manifest, dict) else {}


def get_sqlite_manifest() -> dict[str, Any]:
    return _sqlite_get_meta_value("sqlite_manifest") or {}


def get_opcode_map() -> dict[str, dict[str, Any]]:
    if has_sqlite_bundle():
        return _sqlite_opcode_map()
    opcode_map = get_bundle().get("opcode_map", {})
    return opcode_map if isinstance(opcode_map, dict) else {}


def get_proto_schema() -> dict[str, dict[str, Any]]:
    if has_sqlite_bundle():
        return _sqlite_get_kv("proto_schema") or {"messages": {}, "enums": {}}
    schema = get_bundle().get("proto_schema", {})
    return schema if isinstance(schema, dict) else {"messages": {}, "enums": {}}


def get_blob(name: str) -> bytes | None:
    conn = _connect_sqlite()
    if conn is None:
        path = DATA_DIR / name
        return path.read_bytes() if path.exists() else None
    row = conn.execute("SELECT data FROM blob_store WHERE name=?", (name,)).fetchone()
    return bytes(row["data"]) if row is not None else None


def invalidate_cache() -> None:
    """热重载 / 测试时调用，使下次查询重新读取运行时数据。"""
    global _json_cache, _maps_cache, _sqlite_conn, _sqlite_available
    with _lock:
        _json_cache = None
        _maps_cache = None
        if _sqlite_conn is not None:
            _sqlite_conn.close()
        _sqlite_conn = None
        _sqlite_available = None
