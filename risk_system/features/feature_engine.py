from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from risk_system.domain import Asset, Node, SecurityEvent


@dataclass
class FeatureArtifacts:
    feature_table: pd.DataFrame
    identifiers: pd.DataFrame
    target: Optional[pd.Series] = None


class FeatureEngine:
    def __init__(self) -> None:
        self.preprocessor: Optional[ColumnTransformer] = None

        self.feature_columns_: List[str] = []
        self.numeric_columns_: List[str] = []
        self.categorical_columns_: List[str] = []

        self.fitted_input_columns_: List[str] = []
        self.fitted_numeric_columns_: List[str] = []
        self.fitted_categorical_columns_: List[str] = []

        self.identifier_columns_: List[str] = ["event_id", "node_id", "asset_id", "threat_type"]

    def validate_inputs(
        self,
        events: Sequence[SecurityEvent],
        nodes: Sequence[Node],
        assets: Sequence[Asset],
    ) -> None:
        if not events:
            raise ValueError("Список событий пуст.")
        if not nodes:
            raise ValueError("Список узлов пуст.")
        if not assets:
            raise ValueError("Список активов пуст.")

        event_ids = [event.event_id for event in events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("Идентификаторы событий должны быть уникальными.")

        node_ids = [node.node_id for node in nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("Идентификаторы узлов должны быть уникальными.")

        asset_ids = [asset.asset_id for asset in assets]
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("Идентификаторы активов должны быть уникальными.")

        known_node_ids = set(node_ids)
        known_asset_ids = set(asset_ids)
        node_to_asset = {node.node_id: node.asset_id for node in nodes}

        missing_nodes = [event.event_id for event in events if event.node_id not in known_node_ids]
        if missing_nodes:
            raise ValueError(
                f"Для части событий не найден узел. Примеры event_id: {missing_nodes[:5]}"
            )

        missing_assets = [event.event_id for event in events if event.asset_id not in known_asset_ids]
        if missing_assets:
            raise ValueError(
                f"Для части событий не найден актив. Примеры event_id: {missing_assets[:5]}"
            )

        mismatched_assets = [
            event.event_id
            for event in events
            if event.node_id in node_to_asset and node_to_asset[event.node_id] != event.asset_id
        ]
        if mismatched_assets:
            raise ValueError(
                "Для части событий asset_id не совпадает с asset_id связанного узла. "
                f"Примеры event_id: {mismatched_assets[:5]}"
            )

    def build_feature_table(
        self,
        events: Sequence[SecurityEvent],
        nodes: Sequence[Node],
        assets: Sequence[Asset],
    ) -> pd.DataFrame:
        self.validate_inputs(events, nodes, assets)

        events_df = self._events_to_dataframe(events)
        nodes_df = self._nodes_to_dataframe(nodes)
        assets_df = self._assets_to_dataframe(assets)

        merged = events_df.merge(
            nodes_df,
            on=["node_id", "asset_id"],
            how="left",
            suffixes=("", "_node"),
        )
        merged = merged.merge(
            assets_df,
            on="asset_id",
            how="left",
            suffixes=("", "_asset"),
        )

        if merged[["node_id", "asset_id"]].isnull().any().any():
            raise ValueError("После объединения данных обнаружены пропуски по ключевым полям.")

        merged = self._add_time_features(merged)
        merged = self._normalize_boolean_columns(merged)
        merged = self._fill_missing_values(merged)

        return merged.reset_index(drop=True)

    def fit(
        self,
        feature_table: pd.DataFrame,
        target: Optional[Sequence[int] | pd.Series] = None,
    ) -> Tuple[pd.DataFrame, Optional[pd.Series], pd.DataFrame]:
        prepared = self._prepare_feature_frame(feature_table)
        identifiers = self._extract_identifiers(prepared)
        x_frame = prepared.drop(columns=self.identifier_columns_, errors="ignore").copy()

        self.numeric_columns_ = [
            column for column in x_frame.columns if pd.api.types.is_numeric_dtype(x_frame[column])
        ]
        self.categorical_columns_ = [
            column for column in x_frame.columns if column not in self.numeric_columns_
        ]

        self.feature_columns_ = list(x_frame.columns)
        self.fitted_input_columns_ = list(x_frame.columns)
        self.fitted_numeric_columns_ = list(self.numeric_columns_)
        self.fitted_categorical_columns_ = list(self.categorical_columns_)

        self.preprocessor = ColumnTransformer(
            transformers=[
                ("num", StandardScaler(), self.numeric_columns_),
                ("cat", self._build_one_hot_encoder(), self.categorical_columns_),
            ],
            remainder="drop",
        )

        transformed = self.preprocessor.fit_transform(x_frame)
        feature_names = self.get_feature_names()
        x_transformed = pd.DataFrame(transformed, columns=feature_names, index=x_frame.index)

        y_series = self._build_target(target, x_frame.index)
        return x_transformed, y_series, identifiers

    def transform(self, feature_table: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        if self.preprocessor is None:
            raise RuntimeError("FeatureEngine не обучен. Сначала вызови fit или fit_transform.")

        prepared = self._prepare_feature_frame(feature_table)
        identifiers = self._extract_identifiers(prepared)
        x_frame = prepared.drop(columns=self.identifier_columns_, errors="ignore").copy()

        for column in self.fitted_input_columns_:
            if column not in x_frame.columns:
                if column in self.fitted_numeric_columns_:
                    x_frame[column] = 0.0
                elif column in self.fitted_categorical_columns_:
                    x_frame[column] = "unknown"
                else:
                    x_frame[column] = 0.0

        extra_columns = [column for column in x_frame.columns if column not in self.fitted_input_columns_]
        if extra_columns:
            x_frame = x_frame.drop(columns=extra_columns)

        x_frame = x_frame[self.fitted_input_columns_]

        for column in self.fitted_numeric_columns_:
            if column in x_frame.columns:
                x_frame[column] = pd.to_numeric(x_frame[column], errors="coerce").fillna(0.0)

        for column in self.fitted_categorical_columns_:
            if column in x_frame.columns:
                x_frame[column] = x_frame[column].where(x_frame[column].notna(), "unknown")
                x_frame[column] = x_frame[column].astype(str)

        transformed = self.preprocessor.transform(x_frame)
        feature_names = self.get_feature_names()
        x_transformed = pd.DataFrame(transformed, columns=feature_names, index=x_frame.index)

        return x_transformed, identifiers

    def fit_transform(
        self,
        events: Sequence[SecurityEvent],
        nodes: Sequence[Node],
        assets: Sequence[Asset],
        target: Optional[Sequence[int] | pd.Series | Dict[str, int]] = None,
    ) -> Tuple[pd.DataFrame, Optional[pd.Series], pd.DataFrame, pd.DataFrame]:
        feature_table = self.build_feature_table(events, nodes, assets)
        prepared = self._prepare_feature_frame(feature_table)
        identifiers = self._extract_identifiers(prepared)
        resolved_target = self._resolve_target(target, identifiers)
        x_transformed, y_series, _ = self.fit(prepared, resolved_target)
        return x_transformed, y_series, identifiers, feature_table

    def transform_from_entities(
        self,
        events: Sequence[SecurityEvent],
        nodes: Sequence[Node],
        assets: Sequence[Asset],
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        feature_table = self.build_feature_table(events, nodes, assets)
        x_transformed, identifiers = self.transform(feature_table)
        return x_transformed, identifiers, feature_table

    def get_feature_names(self) -> List[str]:
        if self.preprocessor is None:
            return []

        feature_names = list(self.fitted_numeric_columns_)

        if self.fitted_categorical_columns_:
            cat_transformer = self.preprocessor.named_transformers_["cat"]
            cat_names = list(cat_transformer.get_feature_names_out(self.fitted_categorical_columns_))
            feature_names.extend(cat_names)

        return feature_names

    def _prepare_feature_frame(self, feature_table: pd.DataFrame) -> pd.DataFrame:
        frame = feature_table.copy()

        for column in self.identifier_columns_:
            if column not in frame.columns:
                frame[column] = None

        return frame

    def _extract_identifiers(self, feature_table: pd.DataFrame) -> pd.DataFrame:
        identifier_columns = [
            column for column in self.identifier_columns_ if column in feature_table.columns
        ]
        identifiers = feature_table[identifier_columns].copy()
        return identifiers.reset_index(drop=True)

    def _build_target(
        self,
        target: Optional[Sequence[int] | pd.Series],
        index: pd.Index,
    ) -> Optional[pd.Series]:
        if target is None:
            return None

        if isinstance(target, pd.Series):
            y_series = target.copy().reset_index(drop=True)
            y_series.index = index
            return y_series.astype(int)

        y_series = pd.Series(list(target), index=index, name="target")
        return y_series.astype(int)

    def _resolve_target(
        self,
        target: Optional[Sequence[int] | pd.Series | Dict[str, int]],
        identifiers: pd.DataFrame,
    ) -> Optional[pd.Series]:
        if target is None:
            return None

        if isinstance(target, dict):
            if "event_id" not in identifiers.columns:
                raise ValueError("Невозможно сопоставить target по event_id: колонка event_id отсутствует.")
            resolved = identifiers["event_id"].map(target)
            if resolved.isnull().any():
                missing = identifiers.loc[resolved.isnull(), "event_id"].tolist()[:5]
                raise ValueError(
                    f"Для части событий отсутствуют целевые значения. Примеры event_id: {missing}"
                )
            return resolved.astype(int)

        if isinstance(target, pd.Series):
            if len(target) != len(identifiers):
                raise ValueError("Длина target не совпадает с количеством объектов.")
            return target.astype(int).reset_index(drop=True)

        target_list = list(target)
        if len(target_list) != len(identifiers):
            raise ValueError("Длина target не совпадает с количеством объектов.")
        return pd.Series(target_list, name="target").astype(int)

    def _events_to_dataframe(self, events: Sequence[SecurityEvent]) -> pd.DataFrame:
        rows: List[Dict[str, object]] = []

        for event in events:
            row = event.model_dump(mode="json")
            metadata = row.pop("metadata", {}) or {}
            row.update(self._flatten_metadata(metadata, prefix="event_meta"))
            rows.append(row)

        df = pd.DataFrame(rows)
        if "threat_type" in df.columns:
            df["threat_type"] = df["threat_type"].astype(str)
        return df

    def _nodes_to_dataframe(self, nodes: Sequence[Node]) -> pd.DataFrame:
        rows: List[Dict[str, object]] = []

        for node in nodes:
            row = node.model_dump(mode="json")
            metadata = row.pop("metadata", {}) or {}
            row.update(self._flatten_metadata(metadata, prefix="node_meta"))
            rows.append(row)

        df = pd.DataFrame(rows)
        if "node_type" in df.columns:
            df["node_type"] = df["node_type"].astype(str)
        return df

    def _assets_to_dataframe(self, assets: Sequence[Asset]) -> pd.DataFrame:
        rows: List[Dict[str, object]] = []

        for asset in assets:
            row = asset.model_dump(mode="json")
            metadata = row.pop("metadata", {}) or {}
            row.update(self._flatten_metadata(metadata, prefix="asset_meta"))
            rows.append(row)

        return pd.DataFrame(rows)

    def _flatten_metadata(self, metadata: Dict[str, object], prefix: str) -> Dict[str, object]:
        flat: Dict[str, object] = {}

        for key, value in metadata.items():
            flat_key = f"{prefix}_{key}"
            if isinstance(value, bool):
                flat[flat_key] = int(value)
            elif isinstance(value, (int, float, str)):
                flat[flat_key] = value
            else:
                flat[flat_key] = str(value)

        return flat

    def _add_time_features(self, frame: pd.DataFrame) -> pd.DataFrame:
        result = frame.copy()

        if "timestamp" not in result.columns:
            result["has_timestamp"] = 0
            result["event_hour"] = 0
            result["event_dayofweek"] = 0
            result["event_month"] = 0
            return result

        ts = pd.to_datetime(result["timestamp"], errors="coerce")
        result["has_timestamp"] = ts.notna().astype(int)
        result["event_hour"] = ts.dt.hour.fillna(0).astype(int)
        result["event_dayofweek"] = ts.dt.dayofweek.fillna(0).astype(int)
        result["event_month"] = ts.dt.month.fillna(0).astype(int)
        result = result.drop(columns=["timestamp"])

        return result

    def _normalize_boolean_columns(self, frame: pd.DataFrame) -> pd.DataFrame:
        result = frame.copy()

        for column in result.columns:
            if pd.api.types.is_bool_dtype(result[column]):
                result[column] = result[column].astype(int)

        return result

    def _fill_missing_values(self, frame: pd.DataFrame) -> pd.DataFrame:
        result = frame.copy()

        for column in result.columns:
            if pd.api.types.is_numeric_dtype(result[column]):
                result[column] = result[column].fillna(0)
            else:
                result[column] = result[column].fillna("unknown")

        return result

    @staticmethod
    def _build_one_hot_encoder() -> OneHotEncoder:
        try:
            return OneHotEncoder(handle_unknown="ignore", sparse_output=False)
        except TypeError:
            return OneHotEncoder(handle_unknown="ignore", sparse=False)