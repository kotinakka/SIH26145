"""
Phase 4 — Supervised Random Forest + Unsupervised Isolation Forest trainer.
"""

import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report

MODEL_DIR = os.path.dirname(__file__)
DATASET_CSV = os.path.join(MODEL_DIR, "traffic_dataset.csv")


def train():
    df = pd.read_csv(DATASET_CSV)
    feature_cols = [c for c in df.columns if c not in ("label", "source_pcap")]

    X = df[feature_cols].fillna(0.0)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=14,
        class_weight="balanced",
        random_state=42,
    )
    clf.fit(X_train_s, y_train)

    # 5-fold stratified cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(clf, scaler.transform(X), y, cv=cv, scoring="f1_macro")
    print(f"5-Fold Cross-Validation Macro F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # Unsupervised Isolation Forest trained on benign traffic for anomaly scoring
    iso = IsolationForest(contamination=0.05, random_state=42)
    benign_mask = (y_train == "BENIGN").values
    iso.fit(X_train_s[benign_mask] if benign_mask.sum() > 5 else X_train_s)

    y_pred = clf.predict(X_test_s)
    print("\n========== HOLD-OUT TEST CLASSIFICATION REPORT ==========")
    print(classification_report(y_test, y_pred, digits=3))

    importances = pd.Series(clf.feature_importances_, index=feature_cols).sort_values(ascending=False)
    print("========== TOP 10 ENGINEERED FEATURES ==========")
    for feat, score in importances.head(10).items():
        print(f"  {feat:28s}: {score:.4f}")

    joblib.dump(clf, os.path.join(MODEL_DIR, "rf_threat_model.joblib"))
    joblib.dump(iso, os.path.join(MODEL_DIR, "isolation_forest.joblib"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.joblib"))
    joblib.dump(feature_cols, os.path.join(MODEL_DIR, "feature_columns.joblib"))
    print("\n[SUCCESS] Saved ML artifacts in ml/ folder.")


if __name__ == "__main__":
    train()