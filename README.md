<p align="center">
  <img src="DashBoard.jpg" alt="SOC Dashboard" width="900">
</p>

<h2 align="center">Security Intelligence Platform</h2>
<p align="center"><em>AI-Driven SOC — Wazuh | Suricata | Machine Learning | FastAPI | React</em></p>

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Security Data** | Wazuh, Suricata |
| **Storage** | SQLite |
| **Machine Learning** | scikit-learn, imbalanced-learn |
| **API & Backend** | FastAPI, Uvicorn |
| **Frontend** | React, TypeScript, Vite, Tailwind |
| **Deployment** | Docker, Kubernetes (optional) |

---
## 📚 Table of Contents
- [🧠 Overview](#-overview)
- [🛠️ Tech Stack](#️-tech-stack)
- [⚙️ System Architecture](#️-system-architecture)
- [📦 Structure](#-structure)
- [⚙️ Install & Setup Requirements](#️-install--setup-requirements)
  - [🧩 Python Environment (ML + Backend)](#-1️⃣-python-environment-ml--backend)
  - [🖥️ Node.js Environment (Frontend)](#️-2️⃣-nodejs-environment-frontend)
  - [🗄️ Database Initialization](#️⃣-4️⃣-database-initialization)
- [📊 Model Training & Scoring](#️⃣-5️⃣-train-models-rf--brf)
- [🌐 Run API & Dashboard](#️⃣-7️⃣-start-the-api-fastapi)
- [⚙️ Configuration](#️⃣-9️⃣-configuration)
- [🧪 Testing](#️⃣-🔟-testing)
- [📘 Citation](#-citation)
- [📄 License](#-license)



## 🧠 Overview
This repository contains the **full implementation** of a Machine-Learning-Powered Security Operations Centre (SOC) designed for real-time threat detection, alert prioritisation, and analyst personalisation.

Built with open-source technologies — **Wazuh**, **Suricata**, **FastAPI**, **SQLite**, and **React + Vite** — the platform demonstrates how AI models such as **Random Forest** and **Balanced Random Forest** can significantly reduce false positives and improve analyst efficiency.
---

## 🚀 Quick Start

### Prerequisites
- **Python 3.8+**
- **Node.js 18+** and **npm 9+**
- **Git**
- **SQLite3**


```bash
# Clone the repository
git clone https://github.com/yourusername/Thesis.git
cd Thesis
---
```
## ⚡ One-Command Setup
```bash
git clone https://github.com/saurab123456/Thesis.git
cd Thesis
pip install -r soc-ml-pipeline/ml/requirements.txt
python soc-ml-pipeline/ml/training/train_rf_model_random_forest.py
uvicorn api.main:app --host 0.0.0.0 --port 8000
cd src && npm install && npm run dev
```
## ⚙️ System Architecture
```mermaid
flowchart LR
A[Data Sources] --> B[Data Processing] --> C[Machine Learning] --> D[Dashboard & API]

subgraph A[Data Sources]
A1[Wazuh]
A2[Suricata]
A3[Synthetic Logs]
end

subgraph B[Data Processing]
B1[SQLite Storage]
B2[Feature Engineering]
B3[Normalization]
end

subgraph C[Machine Learning]
C1[Random Forest]
C2[Balanced Random Forest]
C3[Isotonic Calibration]
end

subgraph D[Dashboard & API]
D1[FastAPI Backend]
D2[React Frontend]
D3[Role-Based Views]
end
```
  
### 📦 Structure
- `soc-ml-pipeline/` — data processing, ML training/scoring, configs  
- `api/` — FastAPI backend  
- `src/` — React dashboard (Vite / TypeScript)  
- `config/` — Wazuh / Suricata configuration and MITRE mappings

### Repository Structure
```bash
Thesis/
├─ api/                      # FastAPI backend (REST endpoints for scores & summaries)
├─ soc-ml-pipeline/
│  ├─ data/                  # DB schema/migrations and processed datasets
│  ├─ ml/                    # Model training/evaluation and model artifacts
│  ├─ scripts/               # Scoring and utility scripts
│  └─ config/                # Field maps, lookups (e.g., MITRE), pipeline config
├─ src/                      # React + TypeScript + Vite frontend dashboard
├─ public/                   # Static assets for the front-end
├─ assets/                   # Images/diagrams (screenshots, pipeline figures)
├─ README.md                 # This documentation
├─ requirements.txt          # Python deps for pipeline/API (if consolidated)
└─ .gitignore                # Excludes live DB files, caches, etc.

```
## ⚙️ Install & Setuo Requirements
Before running the SOC pipeline, install all necessary dependencies for both **machine learning** and **API/backend** components.

---

### 🧩 1️⃣ Python Environment (ML + Backend)
Install required Python libraries for model training, alert scoring, and FastAPI backend.

```bash
pip install -r soc-ml-pipeline/ml/requirements.txt

💡 Tip: create a virtual environment
python3 -m venv venv
source venv/bin/activate

```
### 🖥️ 2️⃣ Node.js Environment (Frontend)

Install dependencies for the React + Vite dashboard (**Node v18+**, **npm 9+**):

```bash
cd src
npm install

```

###  4️⃣ Database Initialization
Initialize SQLite database
Requires sqlite3 installed.

```bash

./soc-ml-pipeline/data/sql/init_db.sh ./datasets/wazuh.db

-- inside sqlite3
.tables
SELECT name, sql FROM sqlite_master WHERE type='table';
```
Generate sample data for testing
Ingest Data (Wazuh / Suricata / Synthetic)

Use your ingestion/processing scripts under soc-ml-pipeline/scripts/ (or data/processing/)
Adjust paths to your raw JSON/NDJSON exports.

```bash
python scripts/generate_sample_data.py

python soc-ml-pipeline/scripts/ingest_wazuh_json_to_sqlite.py \
  --input /path/to/wazuh/json \
  --db ./datasets/wazuh.db

python soc-ml-pipeline/scripts/ingest_suricata_to_sqlite.py \
  --input /path/to/suricata/alerts.json \
  --db ./datasets/wazuh.db

```
### 5️⃣ Train Models (RF / BRF)
```bash
python soc-ml-pipeline/ml/training/train_rf_model_random_forest.py \
  --db ./datasets/wazuh.db \
  --outdir soc-ml-pipeline/ml/models

python soc-ml-pipeline/ml/training/evaluate_model_metrics.py
```
Artifacts typically produced:

soc-ml-pipeline/ml/models/rf_model.pkl

soc-ml-pipeline/ml/models/rf_model_clean.pkl (optional sanitized)

soc-ml-pipeline/ml/models/feature_columns.pkl

soc-ml-pipeline/ml/models/label_encoder.pkl

soc-ml-pipeline/ml/models/model_metrics.csv (or written to DB table model_metrics)

soc-ml-pipeline/ml/models/model_feature_importance.csv (or DB table model_feature_importance)

### 6️⃣ Score Alerts & Export Summaries

```bash
python soc-ml-pipeline/scripts/score_alerts_with_rf.py \
  --db ./datasets/wazuh.db \
  --model soc-ml-pipeline/ml/models/rf_model.pkl
```
Common tables/views :

wz_scores_rf, wz_scores_brf, wz_scores_if

v_alerts_scored, v_alerts_scored_rf, v_model_scores_union

model_metrics, model_feature_importance

```sql
-- Number of scored alerts
SELECT COUNT(*) FROM wz_scores_rf;

-- Model metrics
SELECT * FROM model_metrics LIMIT 20;

-- Top 10 important features
SELECT * FROM model_feature_importance ORDER BY importance DESC LIMIT 10;
```

### 7️⃣ Start the API (FastAPI)
```bash
cd api
# If you use uvicorn entrypoint like: main:app
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
Open: http://localhost:8000/
Docs: http://localhost:8000/docs

### 8️⃣ Run the Dashboard (React + Vite)
```bash
cd src
npm run dev
```
Open the printed local URL (e.g., http://localhost:5173) and explore:
```
Real-time scored alerts
Top alert types/severities
Compare Wazuh vs ML scoring (if implemented)
Role-based/analyst-aware views
```
### 9️⃣ Configuration
Create a .env (or .env.local) based on your settings:
Database
DB_PATH=./datasets/wazuh.db

API
API_HOST=0.0.0.0
API_PORT=8000

Frontend
VITE_API_BASE=http://localhost:8000

### 🔟 Testing
Verify Installation
```bash
# Test database
sqlite3 ./datasets/wazuh.db "SELECT COUNT(*) FROM alerts;"

# Test API
curl http://localhost:8000/health

# Test frontend
cd src && npm run build
```
Sample Queries
View scored alerts
```sql
SELECT * FROM v_alerts_scored LIMIT 10;
```
Check model performance
```sql
SELECT model_name, accuracy, precision, recall FROM model_metrics;
