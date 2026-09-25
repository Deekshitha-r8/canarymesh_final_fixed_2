"""UNSW ToN-IoT loader with an offline demo fallback.

Normal operation uses locally downloaded/imported ToN-IoT telemetry.  When the
machine has no network and no dataset files yet, CanaryMesh can still start in
an explicitly labelled offline-demo mode so the UI/backend integration can be
tested.  The demo rows are deterministic and are NOT presented as real
benchmark data.
"""
from __future__ import annotations

import csv
import json
import math
import os
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from database import get_dataset_rows, insert_telemetry_rows, set_dataset_meta, clear_dataset

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

MIRROR_BASE = os.getenv(
    "CANARYMESH_DATA_BASE_URL",
    "https://raw.githubusercontent.com/PengaloGit/ToN_IoT-datasets/main/Train_Test_IoT_dataset",
).rstrip("/")

DATASET_SPECS = {
    "modbus": {"file": "Train_Test_IoT_Modbus.csv", "device_type": "PLC"},
    "weather": {"file": "Train_Test_IoT_Weather.csv", "device_type": "Sensor"},
    "garage_door": {"file": "Train_Test_IoT_Garage_Door.csv", "device_type": "Actuator"},
    "thermostat": {"file": "Train_Test_IoT_Thermostat.csv", "device_type": "Sensor"},
    "fridge": {"file": "Train_Test_IoT_Fridge.csv", "device_type": "Sensor"},
    "motion_light": {"file": "Train_Test_IoT_Motion_Light.csv", "device_type": "Sensor"},
    "gps_tracker": {"file": "Train_Test_IoT_GPS_Tracker.csv", "device_type": "Tracker"},
}
DEFAULT_DATASETS = ["modbus", "weather", "garage_door", "thermostat"]
NORMAL_TYPES = {"normal", "benign"}

FEATURE_ALIASES = {
    "modbus": ["fc1_read_input_register", "fc2_read_discrete_value", "fc3_read_holding_register", "fc4_read_coil"],
    "weather": ["temperature", "pressure", "humidity"],
    "garage_door": ["door_state", "sphone_signal", "sph1e_signal", "sphone_signal_1"],
    "thermostat": ["current_temperature", "thermostat_status"],
    "fridge": ["fridge_temperature", "temp_condition"],
    "motion_light": ["motion_status", "light_status"],
    "gps_tracker": ["latitude", "longitude"],
}


@dataclass(slots=True)
class DatasetRow:
    dataset: str
    source_ts: str
    label: str
    attack_type: str | None
    raw: dict[str, Any]
    features: dict[str, float]
    feature_names: list[str]
    device_type: str


def norm_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


def as_float(value: Any) -> float | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        number = float(str(value).strip())
        return number if math.isfinite(number) else None
    except (TypeError, ValueError):
        return None


def label_value(raw: dict[str, str]) -> str:
    for key, value in raw.items():
        if norm_key(key) == "type" and value:
            return value.strip().lower()
    for key, value in raw.items():
        if norm_key(key) == "label" and value:
            return "attack" if str(value).strip().lower() in {"1", "true", "attack"} else "normal"
    return "normal"


def timestamp_value(raw: dict[str, str]) -> str:
    keys = {norm_key(k): str(v).strip() for k, v in raw.items() if v is not None}
    ts = keys.get("timestamp") or keys.get("ts")
    if ts:
        return ts
    date = keys.get("date", "")
    time = keys.get("time", "")
    return f"{date} {time}".strip() or "unknown"


class DatasetReplayStore:
    def __init__(self, datasets: list[str] | None = None, auto_download: bool = True):
        requested = datasets or [
            x.strip() for x in os.getenv("CANARYMESH_DATASETS", ",".join(DEFAULT_DATASETS)).split(",")
        ]
        self.dataset_names = [d for d in requested if d in DATASET_SPECS] or DEFAULT_DATASETS
        self.auto_download = auto_download
        self.allow_demo_fallback = os.getenv("CANARYMESH_OFFLINE_DEMO", "true").lower() != "false"
        self.rows: dict[str, list[DatasetRow]] = {d: [] for d in self.dataset_names}
        self.normal_rows: dict[str, list[DatasetRow]] = {d: [] for d in self.dataset_names}
        self.attack_rows: dict[str, dict[str, list[DatasetRow]]] = {d: {} for d in self.dataset_names}
        self._normal_cursor = {d: 0 for d in self.dataset_names}
        self._attack_cursor: dict[tuple[str, str], int] = {}
        self.import_stats: list[dict] = []
        self._encoders: dict[str, dict[str, dict[str, float]]] = {}
        self.demo_datasets: set[str] = set()
        self.download_warnings: list[str] = []

    def _path(self, dataset: str) -> Path:
        return DATA_DIR / DATASET_SPECS[dataset]["file"]

    def ensure_files(self) -> None:
        for dataset in self.dataset_names:
            path = self._path(dataset)
            if path.exists() and path.stat().st_size > 0:
                continue
            if not self.auto_download:
                self.download_warnings.append(f"{dataset}: missing {path}")
                continue
            url = f"{MIRROR_BASE}/{DATASET_SPECS[dataset]['file']}"
            try:
                print(f"[CanaryMesh] downloading {dataset} dataset ...")
                with urllib.request.urlopen(url, timeout=20) as response:
                    path.write_bytes(response.read())
            except Exception as exc:
                self.download_warnings.append(f"{dataset}: {exc}")
                if path.exists() and path.stat().st_size == 0:
                    path.unlink(missing_ok=True)

    async def import_into_db(self) -> None:
        self.ensure_files()
        self.import_stats.clear()
        self.demo_datasets.clear()

        for dataset in self.dataset_names:
            path = self._path(dataset)
            csv_rows = self._read_csv(dataset, path) if path.exists() and path.stat().st_size > 0 else []

            if csv_rows:
                await clear_dataset(dataset)
                await insert_telemetry_rows(dataset, [self._row_for_db(row) for row in csv_rows])
                await set_dataset_meta(
                    dataset,
                    "UNSW ToN-IoT benchmark telemetry",
                    "https://research.unsw.edu.au/projects/toniot-datasets",
                    str(path),
                    len(csv_rows),
                )
            else:
                # Reuse an already imported database when offline.
                db_rows = await get_dataset_rows(dataset)
                if not db_rows and self.allow_demo_fallback:
                    demo_rows = self._make_demo_rows(dataset)
                    await clear_dataset(dataset)
                    await insert_telemetry_rows(dataset, [self._row_for_db(row) for row in demo_rows])
                    await set_dataset_meta(
                        dataset,
                        "CanaryMesh offline demo telemetry (NOT ToN-IoT)",
                        "",
                        "built-in deterministic demo rows",
                        len(demo_rows),
                    )
                    self.demo_datasets.add(dataset)

            db_rows = await get_dataset_rows(dataset)
            if not db_rows:
                raise RuntimeError(
                    f"No telemetry is available for '{dataset}'. Put the real ToN-IoT CSV in {DATA_DIR} "
                    "or set CANARYMESH_OFFLINE_DEMO=true for local integration testing."
                )

            self._build_indexes(dataset, db_rows)
            attacks = sum(len(v) for v in self.attack_rows[dataset].values())
            is_demo = dataset in self.demo_datasets
            self.import_stats.append({
                "dataset": dataset,
                "file": str(path),
                "rows": len(db_rows),
                "normal": len(self.normal_rows[dataset]),
                "attacks": attacks,
                "attackTypes": sorted(self.attack_rows[dataset].keys()),
                "source": "offline_demo" if is_demo else "UNSW_ToN-IoT",
                "isDemo": is_demo,
            })

    @staticmethod
    def _row_for_db(row: DatasetRow) -> dict[str, Any]:
        return {
            "device_type": row.device_type,
            "source_ts": row.source_ts,
            "label": row.label,
            "attack_type": row.attack_type,
            "raw": row.raw,
            "features": row.features,
        }

    def _read_csv(self, dataset: str, path: Path) -> list[DatasetRow]:
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                if not reader.fieldnames:
                    return []
                key_map = {norm_key(name): name for name in reader.fieldnames if name}
                self._encoders[dataset] = {}
                rows: list[DatasetRow] = []
                for raw_in in reader:
                    raw = {str(k).strip(): (v if v is not None else "") for k, v in raw_in.items() if k}
                    label = label_value(raw)
                    attack_type = None if label in NORMAL_TYPES else label
                    features, feature_names = self._feature_vector(dataset, raw, key_map)
                    if not features:
                        continue
                    rows.append(DatasetRow(
                        dataset=dataset,
                        source_ts=timestamp_value(raw),
                        label=label,
                        attack_type=attack_type,
                        raw=raw,
                        features=features,
                        feature_names=feature_names,
                        device_type=DATASET_SPECS[dataset]["device_type"],
                    ))
                return rows
        except (OSError, UnicodeError, csv.Error) as exc:
            self.download_warnings.append(f"{dataset}: CSV read failed: {exc}")
            return []

    def _feature_vector(self, dataset: str, raw: dict[str, str], key_map: dict[str, str]) -> tuple[dict[str, float], list[str]]:
        wanted = [alias for alias in FEATURE_ALIASES.get(dataset, []) if alias in key_map]
        if not wanted:
            for nk in key_map:
                if nk in {"label", "type", "date", "time", "ts", "timestamp"}:
                    continue
                value = raw.get(key_map[nk], "")
                if as_float(value) is not None or str(value).strip():
                    wanted.append(nk)
                if len(wanted) >= 8:
                    break

        result: dict[str, float] = {}
        encoder_map = self._encoders.setdefault(dataset, {})
        for nk in wanted:
            value = raw.get(key_map[nk], "")
            number = as_float(value)
            if number is not None:
                result[nk] = number
                continue
            text = str(value).strip().lower()
            if not text:
                continue
            mapping = encoder_map.setdefault(nk, {})
            if text not in mapping:
                mapping[text] = float(len(mapping))
            result[nk] = mapping[text]
        return result, list(result.keys())

    def _make_demo_rows(self, dataset: str) -> list[DatasetRow]:
        """Deterministic offline telemetry for integration testing only.

        The normal section intentionally contains many small variations so the
        Isolation Forest gets a stable baseline. Attack rows are far outside
        that baseline. These rows are explicitly marked offline-demo and must
        never be described as real ToN-IoT data.
        """
        bases = {
            "modbus": ("PLC", FEATURE_ALIASES["modbus"], [10.0, 2.0, 5.0, 1.0], [95.0, 60.0, 80.0, 50.0], [180.0, 100.0, 140.0, 90.0], "demo_command_abuse", "demo_traffic_burst"),
            "weather": ("Sensor", FEATURE_ALIASES["weather"], [24.0, 1012.0, 55.0], [72.0, 930.0, 8.0], [5.0, 970.0, 97.0], "demo_sensor_spike", "demo_weather_extreme"),
            "garage_door": ("Actuator", FEATURE_ALIASES["garage_door"], [0.0, 1.0, 0.0, 1.0], [9.0, 0.0, 9.0, 0.0], [25.0, 25.0, 20.0, 20.0], "demo_state_abuse", "demo_signal_burst"),
            "thermostat": ("Sensor", FEATURE_ALIASES["thermostat"], [22.0, 1.0], [55.0, 0.0], [5.0, 0.0], "demo_temperature_spike", "demo_status_abuse"),
        }
        device_type, feature_names, base, attack_a, attack_b, type_a, type_b = bases[dataset]
        output: list[DatasetRow] = []

        # 80 deterministic normal samples.
        for index in range(80):
            phase = index % 16
            values: list[float] = []
            for j, value in enumerate(base):
                if dataset == "garage_door":
                    # Keep categorical-style demo values in the same normal range.
                    delta = 1.0 if (phase + j) % 9 == 0 else 0.0
                elif dataset == "thermostat" and j == 1:
                    delta = 0.0
                else:
                    delta = ((phase + j * 2) % 5 - 2) * (0.25 if abs(value) < 100 else 0.5)
                values.append(float(value + delta))
            timestamp = f"offline-demo-normal-{index + 1:04d}"
            raw = {name: values[i] for i, name in enumerate(feature_names)}
            raw["type"] = "normal"
            raw["timestamp"] = timestamp
            output.append(DatasetRow(
                dataset=dataset, source_ts=timestamp, label="normal", attack_type=None, raw=raw,
                features={name: values[i] for i, name in enumerate(feature_names)},
                feature_names=list(feature_names), device_type=device_type,
            ))

        for index, (label, values) in enumerate(
            [(type_a, attack_a), (type_a, attack_a), (type_b, attack_b), (type_b, attack_b)], start=1
        ):
            timestamp = f"offline-demo-attack-{index:04d}"
            raw = {name: float(values[i]) for i, name in enumerate(feature_names)}
            raw["type"] = label
            raw["timestamp"] = timestamp
            output.append(DatasetRow(
                dataset=dataset, source_ts=timestamp, label=label, attack_type=label, raw=raw,
                features={name: float(values[i]) for i, name in enumerate(feature_names)},
                feature_names=list(feature_names), device_type=device_type,
            ))
        return output

    def _build_indexes(self, dataset: str, rows: list[dict[str, Any]]) -> None:
        objects: list[DatasetRow] = []
        for row in rows:
            features = {k: float(v) for k, v in row["features"].items()}
            objects.append(DatasetRow(
                dataset=dataset,
                source_ts=row["source_ts"],
                label=row["label"],
                attack_type=row["attack_type"],
                raw=row["raw"],
                features=features,
                feature_names=list(features.keys()),
                device_type=row["device_type"],
            ))
        self.rows[dataset] = objects
        self.normal_rows[dataset] = [r for r in objects if not r.attack_type]
        attacks: dict[str, list[DatasetRow]] = {}
        for row in objects:
            if row.attack_type:
                attacks.setdefault(row.attack_type, []).append(row)
        self.attack_rows[dataset] = attacks
        self._normal_cursor[dataset] = 0
        for key in attacks:
            self._attack_cursor[(dataset, key)] = 0

    def next_normal(self, dataset: str) -> DatasetRow:
        rows = self.normal_rows[dataset]
        if not rows:
            raise RuntimeError(f"No normal rows available for {dataset}")
        index = self._normal_cursor[dataset] % len(rows)
        self._normal_cursor[dataset] += 1
        return rows[index]

    def next_attack(self, dataset: str, attack_type: str | None = None) -> DatasetRow:
        types = sorted(self.attack_rows[dataset])
        if not types:
            raise RuntimeError(f"No attack rows available for {dataset}")
        if attack_type:
            chosen = attack_type.strip().lower()
            if chosen not in self.attack_rows[dataset]:
                raise KeyError(f"Attack type '{attack_type}' is not available in {dataset}")
        else:
            key = (dataset, "__next_type__")
            index = self._attack_cursor.get(key, 0) % len(types)
            chosen = types[index]
            self._attack_cursor[key] = index + 1
        key = (dataset, chosen)
        rows = self.attack_rows[dataset][chosen]
        index = self._attack_cursor.get(key, 0) % len(rows)
        self._attack_cursor[key] = index + 1
        return rows[index]

    def attack_types(self) -> dict[str, list[str]]:
        return {dataset: sorted(self.attack_rows[dataset]) for dataset in self.dataset_names}

    def status(self) -> dict:
        has_demo = bool(self.demo_datasets)
        return {
            "source": "UNSW ToN-IoT" if not has_demo else "UNSW ToN-IoT + offline demo fallback",
            "sourceUrl": "https://research.unsw.edu.au/projects/toniot-datasets",
            "datasets": self.import_stats,
            "totalRows": sum(item["rows"] for item in self.import_stats),
            "totalAttackRows": sum(item["attacks"] for item in self.import_stats),
            "mode": "database_replay" if not has_demo else "offline_demo",
            "demoFallback": has_demo,
            "realDataLoaded": not has_demo,
            "warnings": self.download_warnings[-10:],
        }
