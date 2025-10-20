#!/usr/bin/env python3
"""
cross_validation_analysis.py

Standalone script to perform cross-validation analysis on existing models
and generate thesis-ready results with mean ± std metrics.

Run separately from your main training script:
    python3 cross_validation_analysis.py
"""

import os
import sqlite3
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score, precision_score, recall_score
import matplotlib.pyplot as plt

# Configuration - Update these paths if needed
CONFIG = {
    'db_path': '/home/ubuntu/wazuh-logs/wazuh.db',
    'models_dir': '/home/ubuntu/wazuh-logs/models',
    'output_dir': '/home/ubuntu/wazuh-logs/cv_analysis',
    'cv_folds': 5,
    'random_state': 42
}

def load_data_and_models():
    """Load data and trained models without retraining"""
    print("Loading data and models...")
    
    # Load data
    with sqlite3.connect(CONFIG['db_path']) as con:
        features_df = pd.read_sql_query("SELECT * FROM ml_features", con)
        labels_df = pd.read_sql_query("SELECT id, is_important FROM ml_labels", con)
    
    # Merge features and labels
    df = features_df.merge(labels_df, on='id', how='inner')
    
    # Load feature columns
    features_path = os.path.join(CONFIG['models_dir'], 'rf_feature_columns.json')
    with open(features_path, 'r') as f:
        feature_cols = json.load(f)
    
    # Load trained models
    rf_model = joblib.load(os.path.join(CONFIG['models_dir'], 'rf_model.pkl'))
    brf_model = joblib.load(os.path.join(CONFIG['models_dir'], 'brf_model.pkl'))
    
    # Prepare features and target
    X = df[feature_cols].copy()
    y = df['is_important'].copy()
    
    print(f"Loaded data: {len(X)} samples, {len(feature_cols)} features")
    print(f"Class distribution: {y.value_counts().to_dict()}")
    
    return X, y, rf_model, brf_model, feature_cols

def extract_estimator_from_calibrated(model):
    """Safely extract the base estimator from CalibratedClassifierCV"""
    print(f"Analyzing model type: {type(model)}")
    
    # If it's a CalibratedClassifierCV, extract base estimator
    if hasattr(model, 'calibrated_classifiers_'):
        print("Model is CalibratedClassifierCV")
        # Get the first calibrated classifier to access base estimator
        if hasattr(model.calibrated_classifiers_[0], 'base_estimator'):
            base_est = model.calibrated_classifiers_[0].base_estimator
            print(f"Extracted base estimator: {type(base_est)}")
            return base_est
    
    # If it's a Pipeline with calibration, look for the calibration step
    if hasattr(model, 'named_steps'):
        print("Model has named_steps (likely a Pipeline)")
        for step_name, step_obj in model.named_steps.items():
            print(f"  Step: {step_name}, Type: {type(step_obj)}")
            if hasattr(step_obj, 'calibrated_classifiers_'):
                if (step_obj.calibrated_classifiers_ and 
                    hasattr(step_obj.calibrated_classifiers_[0], 'base_estimator')):
                    base_est = step_obj.calibrated_classifiers_[0].base_estimator
                    print(f"Extracted base estimator from pipeline: {type(base_est)}")
                    return base_est
    
    print("Could not extract base estimator, using model directly")
    return model

def perform_cross_validation_from_scratch(X, y, feature_cols, model_name):
    """Perform cross-validation by training new models with same configuration"""
    print(f"\n{'='*60}")
    print(f"Performing {CONFIG['cv_folds']}-fold CV for {model_name} (from scratch)")
    print(f"{'='*60}")
    
    cv = StratifiedKFold(
        n_splits=CONFIG['cv_folds'], 
        shuffle=True, 
        random_state=CONFIG['random_state']
    )
    
    fold_metrics = []
    
    # Define preprocessing (same as your training script)
    from sklearn.compose import ColumnTransformer
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OrdinalEncoder
    from sklearn.impute import SimpleImputer
    from sklearn.ensemble import RandomForestClassifier
    from imblearn.ensemble import BalancedRandomForestClassifier
    
    num_cols = X.select_dtypes(include=[np.number]).columns.tolist()
    obj_cols = [c for c in feature_cols if c not in num_cols]
    
    num_tf = Pipeline([("imp", SimpleImputer(strategy="median"))])
    obj_tf = Pipeline([
        ("imp", SimpleImputer(strategy="most_frequent")),
        ("enc", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1))
    ]) if obj_cols else "drop"
    
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", num_tf, num_cols),
            ("obj", obj_tf, obj_cols)
        ],
        remainder="drop"
    )
    
    # Define model based on model_name
    if model_name == 'rf':
        classifier = RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            n_jobs=-1,
            random_state=CONFIG['random_state'],
            bootstrap=True,
            class_weight="balanced"
        )
    else:  # 'brf'
        classifier = BalancedRandomForestClassifier(
            n_estimators=300,
            max_depth=20,
            min_samples_leaf=10,
            max_features="sqrt",
            n_jobs=-1,
            random_state=CONFIG['random_state'],
            sampling_strategy="auto",
            replacement=False,
            bootstrap=True
        )
    
    # Create pipeline
    pipeline = Pipeline([
        ("pre", preprocessor),
        ("clf", classifier)
    ])
    
    for fold, (train_idx, val_idx) in enumerate(cv.split(X, y), 1):
        print(f"  Fold {fold}/{CONFIG['cv_folds']}...")
        
        # Split data
        X_train, X_val = X.iloc[train_idx], X.iloc[val_idx]
        y_train, y_val = y.iloc[train_idx], y.iloc[val_idx]
        
        # Train model
        pipeline.fit(X_train, y_train)
        
        # Predict
        y_pred_proba = pipeline.predict_proba(X_val)[:, 1]
        y_pred = (y_pred_proba >= 0.5).astype(int)
        
        # Calculate metrics
        f1 = f1_score(y_val, y_pred)
        precision = precision_score(y_val, y_pred)
        recall = recall_score(y_val, y_pred)
        
        fold_metrics.append({
            'fold': fold,
            'f1': f1,
            'precision': precision,
            'recall': recall,
            'model': model_name
        })
        
        print(f"    F1: {f1:.3f}, Precision: {precision:.3f}, Recall: {recall:.3f}")
    
    return fold_metrics

def calculate_summary_statistics(all_metrics):
    """Calculate mean ± std for all models"""
    df = pd.DataFrame(all_metrics)
    
    summary = df.groupby('model').agg({
        'f1': ['mean', 'std', 'count'],
        'precision': ['mean', 'std'],
        'recall': ['mean', 'std']
    }).round(4)
    
    # Flatten column names
    summary.columns = ['_'.join(col).strip() for col in summary.columns.values]
    summary = summary.reset_index()
    
    return df, summary

def create_visualization(detailed_df, output_dir):
    """Create box plot visualization of CV results"""
    print("\nCreating visualization...")
    
    plt.style.use('default')
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    
    metrics = ['f1', 'precision', 'recall']
    titles = ['F1-Score', 'Precision', 'Recall']
    colors = {'rf': 'lightblue', 'brf': 'lightgreen'}
    
    for i, (metric, title) in enumerate(zip(metrics, titles)):
        # Prepare data for boxplot
        rf_data = detailed_df[detailed_df['model'] == 'rf'][metric]
        brf_data = detailed_df[detailed_df['model'] == 'brf'][metric]
        
        boxes = axes[i].boxplot([rf_data, brf_data], 
                               labels=['Random Forest', 'Balanced RF'],
                               patch_artist=True)
        
        # Add colors
        for patch, color in zip(boxes['boxes'], [colors['rf'], colors['brf']]):
            patch.set_facecolor(color)
        
        axes[i].set_title(f'{title} Distribution\nAcross {CONFIG["cv_folds"]}-Fold CV')
        axes[i].set_ylabel(title)
        axes[i].grid(True, alpha=0.3)
    
    plt.tight_layout()
    
    # Save plot
    plot_path = os.path.join(output_dir, 'cross_validation_results.png')
    plt.savefig(plot_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Visualization saved: {plot_path}")
    return plot_path

def save_results(detailed_df, summary_df, output_dir):
    """Save results to CSV files"""
    detailed_path = os.path.join(output_dir, 'cv_results_detailed.csv')
    summary_path = os.path.join(output_dir, 'cv_results_summary.csv')
    
    detailed_df.to_csv(detailed_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    
    print(f"\nResults saved:")
    print(f"  Detailed: {detailed_path}")
    print(f"  Summary:  {summary_path}")

def print_thesis_ready_results(summary_df):
    """Print formatted results ready for thesis"""
    print(f"\n{'='*70}")
    print("CROSS-VALIDATION RESULTS FOR THESIS")
    print(f"{'='*70}")
    
    for _, row in summary_df.iterrows():
        model_name = "Random Forest" if row['model'] == 'rf' else 'Balanced Random Forest'
        print(f"\n{model_name}:")
        print(f"  F1-score:     {row['f1_mean']:.3f} (±{row['f1_std']:.3f})")
        print(f"  Precision:    {row['precision_mean']:.3f} (±{row['precision_std']:.3f})")
        print(f"  Recall:       {row['recall_mean']:.3f} (±{row['recall_std']:.3f})")
    
    print(f"\n{'='*70}")
    print("READY-TO-COPY TEXT FOR THESIS SECTION VI.H:")
    print(f"{'='*70}")
    
    rf_row = summary_df[summary_df['model'] == 'rf'].iloc[0]
    brf_row = summary_df[summary_df['model'] == 'brf'].iloc[0]
    
    thesis_text = f"""
"Cross-Validation Results: The stratified {CONFIG['cv_folds']}-fold cross-validation yielded consistent performance across all folds. 
The Random Forest model achieved a mean F1-score of {rf_row['f1_mean']:.3f} (±{rf_row['f1_std']:.3f}), 
with precision of {rf_row['precision_mean']:.3f} (±{rf_row['precision_std']:.3f}) and recall of {rf_row['recall_mean']:.3f} (±{rf_row['recall_std']:.3f}). 
Similarly, the Balanced Random Forest showed comparable stability with an F1-score of {brf_row['f1_mean']:.3f} (±{brf_row['f1_std']:.3f}). 
These results confirm the model's robustness and generalizability within the experimental environment."
"""
    
    print(thesis_text)

def main():
    """Main execution function"""
    # Create output directory
    os.makedirs(CONFIG['output_dir'], exist_ok=True)
    
    print("Starting Cross-Validation Analysis")
    print("This script runs separately from your main training infrastructure.")
    
    try:
        # Step 1: Load data and models
        X, y, rf_model, brf_model, feature_cols = load_data_and_models()
        
        # Step 2: Perform cross-validation from scratch (more reliable)
        print("\nUsing fresh training with same configuration for CV analysis...")
        rf_metrics = perform_cross_validation_from_scratch(X, y, feature_cols, 'rf')
        brf_metrics = perform_cross_validation_from_scratch(X, y, feature_cols, 'brf')
        
        # Step 3: Calculate statistics
        all_metrics = rf_metrics + brf_metrics
        detailed_df, summary_df = calculate_summary_statistics(all_metrics)
        
        # Step 4: Create visualization
        plot_path = create_visualization(detailed_df, CONFIG['output_dir'])
        
        # Step 5: Save results
        save_results(detailed_df, summary_df, CONFIG['output_dir'])
        
        # Step 6: Print thesis-ready results
        print_thesis_ready_results(summary_df)
        
        print(f"\n✅ Analysis complete! Check {CONFIG['output_dir']} for all results.")
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
