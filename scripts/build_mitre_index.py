"""Genera app/data/mitre_attack_index.json a partir del bundle STIX oficial de MITRE ATT&CK.

El indice se genera una vez y se versiona: la API NO descarga nada de MITRE en tiempo
de ejecucion (sin trafico de salida por cada alerta, sin dependencia de terceros).

Uso:
    python scripts/build_mitre_index.py                 # descarga el bundle oficial
    python scripts/build_mitre_index.py ruta/enterprise-attack.json
"""
import json
import sys
import urllib.request
from pathlib import Path

BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUT = Path(__file__).resolve().parent.parent / "app" / "data" / "mitre_attack_index.json"


def load_bundle(source: str | None) -> dict:
    if source:
        return json.loads(Path(source).read_text(encoding="utf-8"))
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    with urllib.request.urlopen(BUNDLE_URL, timeout=120) as resp:  # nosec B310  # URL https constante del bundle MITRE
        return json.load(resp)


def attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def is_active(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def main() -> None:
    bundle = load_bundle(sys.argv[1] if len(sys.argv) > 1 else None)
    objects = bundle["objects"]

    version = next(
        (o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"), None
    )
    tactics = {
        o["x_mitre_shortname"]: o["name"]
        for o in objects
        if o["type"] == "x-mitre-tactic" and is_active(o)
    }
    mitigations = {
        o["id"]: {"id": attack_id(o), "name": o["name"]}
        for o in objects
        if o["type"] == "course-of-action" and is_active(o)
    }

    by_stix_id: dict[str, str] = {}
    techniques: dict[str, dict] = {}
    for o in objects:
        if o["type"] != "attack-pattern" or not is_active(o):
            continue
        tid = attack_id(o)
        if not tid:
            continue
        by_stix_id[o["id"]] = tid
        description = (o.get("description") or "").split("\n")[0]
        techniques[tid] = {
            "name": o["name"],
            "tactics": sorted(
                tactics[p["phase_name"]]
                for p in o.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack" and p["phase_name"] in tactics
            ),
            "platforms": o.get("x_mitre_platforms", []),
            "description": description[:400],
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            "mitigations": [],
        }

    for o in objects:
        if o["type"] == "relationship" and o.get("relationship_type") == "mitigates" and is_active(o):
            mit = mitigations.get(o["source_ref"])
            tid = by_stix_id.get(o["target_ref"])
            if mit and tid:
                techniques[tid]["mitigations"].append(mit)
    for tech in techniques.values():
        tech["mitigations"].sort(key=lambda m: m["id"] or "")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {"attack_version": version, "tactics": sorted(tactics.values()), "techniques": techniques},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    print(f"{len(techniques)} tecnicas, {len(tactics)} tacticas (ATT&CK v{version}) -> {OUT}")


if __name__ == "__main__":
    main()
