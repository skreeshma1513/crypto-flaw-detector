"""Trains a RandomForest on data/training_data.csv and saves ai_model/model.pkl."""
import os, sys
import joblib, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV = os.path.join(ROOT, "data", "training_data.csv")
MODEL = os.path.join(ROOT, "ai_model", "model.pkl")


def train(verbose=True):
    if not os.path.exists(CSV):                  # build the dataset if it is missing
        sys.path.insert(0, os.path.join(ROOT, "data"))
        import runpy; runpy.run_path(os.path.join(ROOT, "data", "generate_training_data.py"))
    df = pd.read_csv(CSV)
    X, y = df.drop(columns=["risk_category"]), df["risk_category"]
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    clf = RandomForestClassifier(n_estimators=150, max_depth=8, random_state=42).fit(Xtr, ytr)
    acc = accuracy_score(yte, clf.predict(Xte))
    joblib.dump({"model": clf, "features": list(X.columns)}, MODEL)
    if verbose:
        print(f"Model trained on {len(Xtr)} rows, test accuracy = {acc:.2%}\nSaved to {MODEL}")
    return acc


if __name__ == "__main__":
    train()
