# Thesis

This repository contains the thesis frontend (React + Vite) and the SOC ML pipeline.

## 📦 Structure
- `soc-ml-pipeline/` — data processing, ML training/scoring, configs
- `api/` — FastAPI backend (if used here)
- `src/` — React dashboard (Vite/TS)

## 📂 Appendix A: Repository Structure
\`\`\`text
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
\`\`\`

## 🚀 Quick start (ML)
\`\`\`bash
pip install -r soc-ml-pipeline/ml/requirements.txt
python soc-ml-pipeline/ml/training/train_rf_model_random_forest.py
\`\`\`

---

### 🗄️ Create the SQLite database (schema only)

Requires `sqlite3` installed.

```bash
# From repo root
./soc-ml-pipeline/data/sql/init_db.sh ./datasets/wazuh.db

# or to create alerts.db
./soc-ml-pipeline/data/sql/init_db.sh ./datasets/alerts.db


---

### 🧠 Load Pretrained Models

This repository includes pretrained Random Forest models for reproducibility.

```python
import joblib
model = joblib.load("soc-ml-pipeline/ml/models/rf_model.pkl")
features = joblib.load("soc-ml-pipeline/ml/models/feature_columns.pkl")
print(f"Loaded model with {len(features)} features")
