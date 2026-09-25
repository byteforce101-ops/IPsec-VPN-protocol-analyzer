"""
AI Traffic Classifier Trainer for IPsec Encrypted Flows.
Trains a Scikit-Learn Random Forest model to predict encrypted traffic categories
(Web, Video, VoIP, FileTransfer, ICMP) based on flow statistics.
"""

import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split

AI_DIR = os.path.dirname(__file__)
DATASET_PATH = os.path.abspath(os.path.join(AI_DIR, "..", "..", "dataset", "vpn_traffic_dataset.csv"))
MODEL_PATH = os.path.join(AI_DIR, "traffic_classifier.pkl")

# Feature columns used for training
FEATURE_COLS = [
    "flow_duration",
    "packet_count",
    "bytes_total",
    "avg_pkt_size",
    "std_pkt_size",
    "max_pkt_size",
    "min_pkt_size",
    "packets_per_sec",
    "bytes_per_sec",
]


def train_ai_model():
    if not os.path.exists(DATASET_PATH):
        from dataset_generator import generate_dataset
        generate_dataset()

    df = pd.read_csv(DATASET_PATH)
    X = df[FEATURE_COLS]
    y = df["traffic_category"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print("=" * 60)
    print(f"AI TRAFFIC CLASSIFIER MODEL - TRAINING RESULTS")
    print("=" * 60)
    print(f"Overall Accuracy : {acc * 100:.2f}%\n")
    print("Classification Report:")
    print(classification_report(y_test, y_pred))

    joblib.dump(clf, MODEL_PATH)
    print(f"Trained model saved to: {MODEL_PATH}")
    return clf


if __name__ == "__main__":
    train_ai_model()
