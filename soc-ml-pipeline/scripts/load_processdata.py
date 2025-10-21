import pandas as pd
import sqlite3
import numpy as np
from matplotlib import pyplot as plt
import seaborn as sns
from scipy import stats

def load_and_process_data(db_path='alerts.db'):
    """Load and process survey data from SQLite database."""
    try:
        # Connect to database and load data
        conn = sqlite3.connect(db_path)
        df = pd.read_sql("SELECT * FROM survey_responses", conn)
        conn.close()
        
        # Validate data was loaded
        if df.empty:
            raise ValueError("No data found in the survey_responses table")
            
        # Convert cognitive responses to numeric
        cognitive_questions = [f'statement_2_{i}' for i in range(1, 6)]
        cognitive_mapping = {
            'True': 1, 
            'False': 0, 
            'Uncertain': 0.5,
            np.nan: 0.5  # Handle missing values as neutral
        }
        
        for q in cognitive_questions:
            if q in df.columns:
                df[q] = df[q].map(cognitive_mapping).fillna(0.5)  # Default to neutral if unexpected value
            else:
                print(f"Warning: Column {q} not found in data")
        
        # Calculate composite scores (with error handling for missing columns)
        required_columns = ['statement_2_1', 'statement_2_2', 'statement_2_3', 'statement_2_4', 'statement_2_5']
        if all(col in df.columns for col in required_columns):
            df['analytic_score'] = df['statement_2_1'] + df['statement_2_4'] + df['statement_2_5']
            df['intuitive_score'] = df['statement_2_2'] + df['statement_2_3']
            df['cognitive_balance'] = df['analytic_score'] - df['intuitive_score']
            
            # Classify respondents
            conditions = [
                (df['cognitive_balance'] > 1),
                (df['cognitive_balance'] < -1),
                (abs(df['cognitive_balance']) <= 1)
            ]
            choices = ['Analytic', 'Intuitive', 'Balanced']
            df['cognitive_style'] = np.select(conditions, choices, default='Balanced')
        else:
            print("Warning: Missing required columns for score calculation")
            
        return df
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    except Exception as e:
        print(f"Error processing data: {e}")
        return None

# Usage
df = load_and_process_data()

if df is not None:
    print("Data loaded successfully!")
    print(df.head())
    print("\nCognitive style distribution:")
    print(df['cognitive_style'].value_counts())
else:
    print("Failed to load data")
