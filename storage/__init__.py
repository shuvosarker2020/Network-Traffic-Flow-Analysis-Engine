"""
Storage Engine Factory for AegisFlow
"""

import os
from typing import Optional
from storage.engine import BaseStorageEngine
from storage.duckdb_driver import DuckDBStorageEngine
from storage.clickhouse_driver import ClickHouseStorageEngine

_global_storage: Optional[BaseStorageEngine] = None

def get_storage_engine(config: Optional[dict] = None) -> BaseStorageEngine:
    global _global_storage
    if _global_storage is not None:
        return _global_storage

    cfg = config or {}
    storage_cfg = cfg.get("storage", {})
    engine_type = storage_cfg.get("engine", "duckdb").lower()

    if engine_type == "clickhouse":
        ch_cfg = storage_cfg.get("clickhouse", {})
        engine = ClickHouseStorageEngine(
            host=ch_cfg.get("host", "localhost"),
            port=ch_cfg.get("port", 8123),
            user=ch_cfg.get("user", "default"),
            password=ch_cfg.get("password", ""),
            database=ch_cfg.get("database", "aegisflow")
        )
        if engine.client:
            _global_storage = engine
            return engine
        # Fallback to duckdb if ClickHouse is unreachable
        print("ClickHouse cluster not reachable; falling back to embedded DuckDB OLAP engine.")

    # Default: DuckDB
    duck_cfg = storage_cfg.get("duckdb", {})
    db_path = duck_cfg.get("path", "data/aegisflow.duckdb")
    threads = duck_cfg.get("threads", 4)
    _global_storage = DuckDBStorageEngine(db_path=db_path, threads=threads)
    return _global_storage
