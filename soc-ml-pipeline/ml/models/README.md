# Pretrained Models
- rf_model.pkl
- rf_model_clean.pkl
- feature_columns.pkl
- feature_columns_clean.pkl
- label_encoder.pkl

Load with joblib:
```python
import joblib
model = joblib.load("soc-ml-pipeline/ml/models/rf_model.pkl")

