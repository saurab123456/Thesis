<p align="center">
  <img src="DashBoard.jpg" alt="SOC Dashboard" width="900">
</p>

<h2 align="center">Security Intelligence Platform</h2>
<p align="center"><em>AI-Driven SOC — Wazuh | Suricata | Machine Learning | FastAPI | React</em></p>

---

## 🧠 Overview
This repository contains the **full implementation** of a Machine-Learning-Powered Security Operations Centre (SOC) designed for real-time threat detection, alert prioritisation, and analyst personalisation.

Built with open-source technologies — **Wazuh**, **Suricata**, **FastAPI**, **SQLite**, and **React + Vite** — the platform demonstrates how AI models such as Random Forest and Balanced Random Forest can significantly reduce false positives and improve analyst efficiency.

---

## 📦 Structure
- `soc-ml-pipeline/` — data processing, ML training/scoring, configs  
- `api/` — FastAPI backend (if used here)  
- `src/` — React dashboard (Vite/TS)  

---

## 📂 Appendix A: Repository Structure
```text
soc-ml-pipeline/
├── data/
│   ├── sql/                   # Database schema & migrations
│   └── processing/            # Ingestion & feature pipelines
├── ml/
│   ├── training/              # Model training & evaluation
│   └── models/                # (Optional) Serialized models via Git LFS or Releases
├── scripts/                   # Online scoring & publishing helpers
├── api/                       # (Optional) FastAPI backend
├── dashboard/                 # (Optional) React frontend (if separated)
└── config/                    # Wazuh/Suricata config, MITRE lookups, field maps

## 📂 Install Requirements

1️⃣ pip install -r soc-ml-pipeline/ml/requirements.txt

2️⃣ Train Model
python soc-ml-pipeline/ml/training/train_rf_model_random_forest.py

🗄️ Create the SQLite Database (Schema Only)

Requires sqlite3 installed.

# From repo root
./soc-ml-pipeline/data/sql/init_db.sh ./datasets/wazuh.db

# or to create alerts.db
./soc-ml-pipeline/data/sql/init_db.sh ./datasets/alerts.db

🧠 Load Pretrained Models

This repository includes pretrained Random Forest models for reproducibility.

import joblib

model = joblib.load("soc-ml-pipeline/ml/models/rf_model.pkl")
features = joblib.load("soc-ml-pipeline/ml/models/feature_columns.pkl")
print(f"Loaded model with {len(features)} features")

📊 Key Features

Integrated Data Sources: Wazuh, Suricata, and synthetic datasets

Machine-Learning Pipeline: Random Forest & Balanced Random Forest with isotonic calibration

Dynamic Personalisation: Analyst-specific dashboards and cognitive trust adaptation

Visual Analytics: Real-time alert scoring, top 10 alert types, and severity distribution

Scalable Deployment: FastAPI + React stack deployable via Docker or Kubernetes

🧱 Tech Stack
Layer	Technology
Backend / API	FastAPI • SQLite • Python
Frontend	React • TypeScript • Tailwind • Vite
Machine Learning	scikit-learn • imbalanced-learn
Security Engines	Wazuh • Suricata
Deployment	Docker • Kubernetes (Ronin Cloud Cluster)
