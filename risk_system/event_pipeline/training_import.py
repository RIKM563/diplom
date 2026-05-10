from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List

from .schemas import RiskEventClassifierFlatTrainingSample


class RiskEventTrainingSampleImporter:
    def parse_file(
        self,
        filename: str,
        content: bytes,
    ) -> List[RiskEventClassifierFlatTrainingSample]:
        if not content:
            raise ValueError("Файл обучающей выборки пуст.")

        normalized_filename = filename.lower().strip()

        if normalized_filename.endswith(".csv"):
            return self._parse_csv(content)

        if normalized_filename.endswith(".json"):
            return self._parse_json(content)

        raise ValueError("Поддерживаются только файлы .csv и .json.")

    def _parse_csv(self, content: bytes) -> List[RiskEventClassifierFlatTrainingSample]:
        text = content.decode("utf-8-sig")

        sample = text[:2048]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(io.StringIO(text), dialect=dialect)

        if not reader.fieldnames:
            raise ValueError("CSV-файл не содержит заголовков столбцов.")

        rows = list(reader)

        if not rows:
            raise ValueError("CSV-файл не содержит строк обучающей выборки.")

        return [
            RiskEventClassifierFlatTrainingSample(**self._clean_record(row))
            for row in rows
        ]

    def _parse_json(self, content: bytes) -> List[RiskEventClassifierFlatTrainingSample]:
        text = content.decode("utf-8-sig")
        payload = json.loads(text)

        if isinstance(payload, dict):
            rows = payload.get("samples")
        else:
            rows = payload

        if not isinstance(rows, list):
            raise ValueError(
                "JSON-файл должен содержать список объектов или объект вида {'samples': [...]}."
            )

        if not rows:
            raise ValueError("JSON-файл не содержит строк обучающей выборки.")

        result: List[RiskEventClassifierFlatTrainingSample] = []

        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Каждая запись обучающей выборки должна быть JSON-объектом.")

            result.append(
                RiskEventClassifierFlatTrainingSample(**self._clean_record(row))
            )

        return result

    def _clean_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        cleaned: Dict[str, Any] = {}

        for key, value in record.items():
            normalized_key = str(key).strip()

            if not normalized_key:
                continue

            if value is None:
                continue

            if isinstance(value, str):
                value = value.strip()

                if value == "":
                    continue

                if value.lower() in {"true", "yes", "да"}:
                    cleaned[normalized_key] = True
                    continue

                if value.lower() in {"false", "no", "нет"}:
                    cleaned[normalized_key] = False
                    continue

            cleaned[normalized_key] = value

        return cleaned