"""Inventario de red de SOLO LECTURA (Lab 3, linea Network Automation Hub).

Fuente: app/data/network_inventory.json (datos ficticios, sin credenciales). La app no tiene
ningun endpoint de escritura sobre el inventario ni ejecuta nada contra los dispositivos: el
Runner con aprobacion y rollback pertenece a laboratorios posteriores.
"""
import json
from functools import lru_cache
from pathlib import Path

INVENTORY_PATH = Path(__file__).resolve().parent / "data" / "network_inventory.json"


@lru_cache(maxsize=1)
def load() -> dict[str, dict]:
    data = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    return {d["id"]: d for d in data["devices"]}


def list_devices(device_type: str | None = None) -> list[dict]:
    return [d for d in load().values() if device_type in (None, d["type"])]


def get_device(device_id: str) -> dict | None:
    return load().get(device_id)
