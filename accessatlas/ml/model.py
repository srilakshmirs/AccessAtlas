"""Unsupervised behavioural anomaly detection using Isolation Forest.

Fits separate IsolationForest estimators on unlabelled human and service account
activity and entitlement features. Anomaly cutoffs are determined using an alert
budget percentile defined in configuration.

Note: The service-account model has only about 159 train identities.
This is a small sample, which limits estimator degrees of freedom compared to
the human population (~3,081 train identities).
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from accessatlas.ml.features import (
    HUMAN_FEATURE_COLS,
    SERVICE_FEATURE_COLS,
)
from accessatlas.rules.models import Finding
from accessatlas.utils import load_config

logger = logging.getLogger(__name__)


class BehavioralAnomalyDetector:
    """Unsupervised anomaly detector leveraging Isolation Forests.

    Fits independent estimators for human and service identities to capture distinct
    operational baseline behaviors across activity, volume, off-hours, and privileges.
    """

    def __init__(
        self,
        alert_budget_percentile: float | None = None,
        random_state: int = 42,
        n_estimators: int = 100,
    ) -> None:
        """Initialize the anomaly detector.

        Parameters
        ----------
        alert_budget_percentile : float, optional
            Percentage of identities to flag as anomalous (e.g. 2.5 means top 2.5%).
            If None, loaded from config.yaml (`ml.alert_budget_percentile`).
        random_state : int, default 42
            Random seed for IsolationForest reproducibility.
        n_estimators : int, default 100
            Number of decision trees in each forest.
        """
        cfg = load_config()
        ml_cfg = cfg.get("ml", {}) if isinstance(cfg.get("ml"), dict) else {}

        if alert_budget_percentile is not None:
            self.alert_budget_percentile = float(alert_budget_percentile)
        else:
            self.alert_budget_percentile = float(ml_cfg.get("alert_budget_percentile", 2.5))

        self.random_state = int(ml_cfg.get("random_state", random_state))
        self.n_estimators = int(ml_cfg.get("n_estimators", n_estimators))

        self.human_model: IsolationForest | None = None
        self.service_model: IsolationForest | None = None

        self.human_threshold: float = 0.0
        self.service_threshold: float = 0.0
        self.is_fitted: bool = False

    def fit(self, feature_df: pd.DataFrame) -> BehavioralAnomalyDetector:
        """Fit the models on unlabelled training feature vectors.

        Note: The service-account model has only about 159 train identities,
        which represents a small sample size.

        Parameters
        ----------
        feature_df : pd.DataFrame
            Extracted behavioral feature DataFrame from extract_behavioral_features.

        Returns
        -------
        BehavioralAnomalyDetector
            Fitted instance.
        """
        humans = feature_df[feature_df["identity_kind"] == "human"].copy()
        services = feature_df[feature_df["identity_kind"] == "service"].copy()

        logger.info(
            "Fitting BehavioralAnomalyDetector: %d humans, %d service accounts (small sample).",
            len(humans),
            len(services),
        )

        # Fit Human Model
        if not humans.empty:
            X_h = humans[HUMAN_FEATURE_COLS].fillna(0.0)
            self.human_model = IsolationForest(
                n_estimators=self.n_estimators,
                random_state=self.random_state,
                contamination="auto",
            )
            self.human_model.fit(X_h)
            # Invert decision function: higher score = more anomalous
            h_scores = -self.human_model.decision_function(X_h)
            self.human_threshold = float(
                np.percentile(h_scores, 100.0 - self.alert_budget_percentile)
            )
        else:
            self.human_threshold = 0.0

        # Fit Service Account Model
        if not services.empty:
            X_s = services[SERVICE_FEATURE_COLS].fillna(0.0)
            self.service_model = IsolationForest(
                n_estimators=self.n_estimators,
                random_state=self.random_state,
                contamination="auto",
            )
            self.service_model.fit(X_s)
            s_scores = -self.service_model.decision_function(X_s)
            self.service_threshold = float(
                np.percentile(s_scores, 100.0 - self.alert_budget_percentile)
            )
        else:
            self.service_threshold = 0.0

        self.is_fitted = True
        return self

    def score(self, feature_df: pd.DataFrame) -> pd.DataFrame:
        """Calculate continuous anomaly scores and binary anomaly flags.

        Parameters
        ----------
        feature_df : pd.DataFrame
            Feature DataFrame.

        Returns
        -------
        pd.DataFrame
            Copy of input DataFrame augmented with 'anomaly_score', 'anomaly_threshold',
            and 'is_anomaly'.
        """
        if not self.is_fitted:
            raise RuntimeError("BehavioralAnomalyDetector must be fitted before scoring.")

        result = feature_df.copy()
        result["anomaly_score"] = 0.0
        result["anomaly_threshold"] = 0.0
        result["is_anomaly"] = False

        # Human scoring
        h_mask = result["identity_kind"] == "human"
        if h_mask.any() and self.human_model is not None:
            X_h = result.loc[h_mask, HUMAN_FEATURE_COLS].fillna(0.0)
            scores_h = -self.human_model.decision_function(X_h)
            result.loc[h_mask, "anomaly_score"] = scores_h
            result.loc[h_mask, "anomaly_threshold"] = self.human_threshold
            result.loc[h_mask, "is_anomaly"] = scores_h >= self.human_threshold

        # Service scoring
        s_mask = result["identity_kind"] == "service"
        if s_mask.any() and self.service_model is not None:
            X_s = result.loc[s_mask, SERVICE_FEATURE_COLS].fillna(0.0)
            scores_s = -self.service_model.decision_function(X_s)
            result.loc[s_mask, "anomaly_score"] = scores_s
            result.loc[s_mask, "anomaly_threshold"] = self.service_threshold
            result.loc[s_mask, "is_anomaly"] = scores_s >= self.service_threshold

        return result

    def generate_findings(
        self,
        scored_df: pd.DataFrame,
        peer_medians: dict[str, dict[str, float]],
        peer_stds: dict[str, dict[str, float]],
        resolved_identities: pd.DataFrame | None = None,
        suppression_engine: Any | None = None,
    ) -> list[Finding]:
        """Convert detected anomalies into structured explainable Finding objects.

        For each anomalous identity, extracts the top 3 deviating features relative
        to the unlabelled peer baseline (value, peer median, and z-score).
        Optionally filters out anomalies suppressed by legitimate administrative context.

        Parameters
        ----------
        scored_df : pd.DataFrame
            DataFrame produced by self.score().
        peer_medians : dict
            Peer group medians per feature.
        peer_stds : dict
            Peer group standard deviations per feature.
        resolved_identities : pd.DataFrame, optional
            Resolved identities table to populate platform associations.
        suppression_engine : SuppressionEngine, optional
            Context suppression engine to filter legitimate administrative activity.

        Returns
        -------
        list[Finding]
            List of standardized anomaly findings.
        """
        # Map platforms for each identity
        plat_map: dict[str, list[str]] = {}
        if resolved_identities is not None and not resolved_identities.empty:
            for _, r in resolved_identities.iterrows():
                iid = str(r["identity_id"])
                p_list: list[str] = []
                if pd.notna(r.get("ad_account_id")) and r.get("ad_account_id"):
                    p_list.append("ad")
                if pd.notna(r.get("aws_user_id")) and r.get("aws_user_id"):
                    p_list.append("aws")
                if pd.notna(r.get("okta_id")) and r.get("okta_id"):
                    p_list.append("okta")
                plat_map[iid] = p_list

        findings: list[Finding] = []
        anomalies = scored_df[scored_df["is_anomaly"]].copy()

        # Features to inspect for evidence deviation
        eval_features = [
            "events_per_day",
            "off_hours_share",
            "distinct_ips",
            "distinct_countries",
            "max_bytes_transferred",
            "total_bytes_transferred",
            "failure_rate",
            "privileged_action_share",
            "total_groups_count",
            "effective_tier_score",
            "privilege_utilization_gap",
            "token_count",
        ]

        for _, row in anomalies.iterrows():
            iid = str(row["identity_id"])
            ikind = str(row["identity_kind"])
            pg = str(row.get("peer_group", "Unknown"))
            score_val = float(row["anomaly_score"])
            thresh_val = float(row["anomaly_threshold"])

            meds = peer_medians.get(pg, {})
            stds = peer_stds.get(pg, {})

            # Compute deviations across features
            feature_deviations: list[dict[str, Any]] = []
            for feat in eval_features:
                if feat not in row or pd.isna(row[feat]):
                    continue
                val = float(row[feat])
                med = float(meds.get(feat, 0.0))
                std = max(1e-4, float(stds.get(feat, 1.0)))
                z = (val - med) / std

                # Track deviation magnitude
                feature_deviations.append(
                    {
                        "feature": feat,
                        "value": val,
                        "median": med,
                        "z_score": z,
                        "abs_z": abs(z),
                    }
                )

            # Sort by highest absolute z-score
            feature_deviations.sort(key=lambda x: x["abs_z"], reverse=True)
            top_3 = feature_deviations[:3]

            # Format top 3 deviating features with value, peer median, and z-score
            evidence_lines: list[str] = [
                f"Behavioural anomaly score {score_val:.3f} exceeds baseline cutoff {thresh_val:.3f} "
                f"(alert budget {self.alert_budget_percentile}%)."
            ]
            for dev in top_3:
                evidence_lines.append(
                    f"{dev['feature']}: value={dev['value']:.2f}, "
                    f"peer median={dev['median']:.2f}, z-score={dev['z_score']:+.2f}"
                )

            plats = plat_map.get(iid, ["ad" if ikind == "human" else "aws"])
            if not plats:
                plats = ["ad"]

            if suppression_engine is not None:
                is_supp, reason = suppression_engine.check_suppression(
                    rule="behavioural_anomaly",
                    identity_id=iid,
                    platforms=plats,
                    account_id=None,
                )
                if is_supp:
                    logger.debug("Suppressed behavioural anomaly for %s: %s", iid, reason)
                    continue

            fnd = Finding(
                finding_id=f"FND-behavioural_anomaly-{iid}",
                rule="behavioural_anomaly",
                identity_id=iid,
                account_id=None,
                platforms=plats,
                severity="medium",
                evidence=evidence_lines,
                privilege_path=None,
                recommended_action=(
                    "Investigate anomalous identity behavior. Compare activity, off-hours volume, "
                    "or elevated privilege profile against peer group baseline."
                ),
                confidence_caveat=None,
            )
            findings.append(fnd)

        return findings
