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

---

## ⚡ Quick Start

### 1️⃣ Install Requirements
```bash
pip install -r soc-ml-pipeline/ml/requirements.txt
