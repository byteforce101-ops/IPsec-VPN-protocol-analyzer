"""
AI Traffic Classifier Trainer for IPsec Encrypted Flows.
Trains a statistical feature-space classifier on flow statistics
(Web, Video, VoIP, WhatsApp, Email, FileTransfer, ICMP).
Saves trained model parameters to backend/ai/traffic_classifier_model.json.
"""

import csv
import json
import math
import os
import random

AI_DIR = os.path.dirname(__file__)
DATASET_PATH = os.path.abspath(os.path.join(AI_DIR, "..", "..", "dataset", "vpn_traffic_dataset.csv"))
MODEL_JSON_PATH = os.path.join(AI_DIR, "traffic_classifier_model.json")

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


def load_dataset(csv_path: str):
    rows = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            features = [float(row[col]) for col in FEATURE_COLS]
            label = row["traffic_category"]
            rows.append((features, label))
    return rows


def normalize(vector, min_vec, max_vec):
    norm = []
    for i in range(len(vector)):
        denom = max_vec[i] - min_vec[i]
        val = (vector[i] - min_vec[i]) / denom if denom > 0 else 0.0
        norm.append(val)
    return norm


def train_ai_model():
    if not os.path.exists(DATASET_PATH):
        from dataset_generator import generate_dataset
        generate_dataset()

    dataset = load_dataset(DATASET_PATH)
    random.seed(42)
    random.shuffle(dataset)

    split = int(0.8 * len(dataset))
    train_set = dataset[:split]
    test_set = dataset[split:]

    num_features = len(FEATURE_COLS)
    min_vec = [min(row[0][i] for row in dataset) for i in range(num_features)]
    max_vec = [max(row[0][i] for row in dataset) for i in range(num_features)]

    # Compute class centroids in normalized feature space
    categories = list(set(row[1] for row in dataset))
    centroids = {cat: [0.0] * num_features for cat in categories}
    counts = {cat: 0 for cat in categories}

    for feats, label in train_set:
        norm_feats = normalize(feats, min_vec, max_vec)
        for i in range(num_features):
            centroids[label][i] += norm_feats[i]
        counts[label] += 1

    for cat in categories:
        if counts[cat] > 0:
            centroids[cat] = [val / counts[cat] for val in centroids[cat]]

    # Evaluate accuracy on test set using nearest centroid in weighted space
    correct = 0
    feature_weights = [1.0, 1.2, 1.5, 2.5, 2.0, 2.0, 1.5, 1.0, 1.2]

    for feats, true_label in test_set:
        norm_feats = normalize(feats, min_vec, max_vec)
        best_cat = None
        min_dist = float("inf")

        for cat, centroid in centroids.items():
            dist = math.sqrt(sum(w * (nf - c) ** 2 for w, nf, c in zip(feature_weights, norm_feats, centroid)))
            if dist < min_dist:
                min_dist = dist
                best_cat = cat

        if best_cat == true_label:
            correct += 1

    accuracy = correct / max(len(test_set), 1)

    model_data = {
        "categories": categories,
        "feature_cols": FEATURE_COLS,
        "feature_weights": feature_weights,
        "min_vec": min_vec,
        "max_vec": max_vec,
        "centroids": centroids,
        "accuracy": round(accuracy * 100, 2),
    }

    with open(MODEL_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(model_data, f, indent=2)

    print("=" * 60)
    print("AI TRAFFIC CLASSIFIER MODEL - TRAINING RESULTS")
    print("=" * 60)
    print(f"Total Training Samples : {len(train_set)}")
    print(f"Total Test Samples     : {len(test_set)}")
    print(f"Categories Trained     : {', '.join(categories)}")
    print(f"Test Set Accuracy      : {accuracy * 100:.2f}%")
    print(f"Model saved to         : {MODEL_JSON_PATH}")
    print("=" * 60)

    return model_data


if __name__ == "__main__":
    train_ai_model()
