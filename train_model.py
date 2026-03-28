import os
import glob
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_selection import RFE
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score, 
    precision_score, recall_score, f1_score, roc_curve, auc, 
    precision_recall_curve
)
from imblearn.over_sampling import SMOTE
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Conv1D, BatchNormalization, MaxPooling1D, Dropout, LSTM, Dense
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

# Set random seed for reproducibility
np.random.seed(42)
tf.random.set_seed(42)

def load_data():
    print("  Loading and Merging Datasets...")
    dataset_path = 'dataset/'
    all_files = glob.glob(os.path.join(dataset_path, "*.csv"))
    
    if not all_files:
        if os.path.exists('archive'):
            all_files = glob.glob(os.path.join('archive', "*.csv"))
    
    if not all_files:
        raise FileNotFoundError("No CSV files found in dataset/ or archive/")
        
    li = []
    for filename in all_files:
        try:
            df_temp = pd.read_csv(filename, index_col=None, header=0, low_memory=False)
            li.append(df_temp)
        except Exception as e:
            print(f"  Error loading {filename}: {e}")

    df = pd.concat(li, axis=0, ignore_index=True)
    
    if 'Label' not in df.columns:
        possible_labels = [c for c in df.columns if c.lower() == 'label']
        if possible_labels:
            df.rename(columns={possible_labels[0]: 'Label'}, inplace=True)
        else:
            raise ValueError("Label column not found!")
    
    return df

def preprocess_data(df):
    print("  Preprocessing Data...")
    cols_to_drop = [
        'id', 'expiration_id', 'src_ip', 'src_mac', 'src_oui', 
        'dst_ip', 'dst_mac', 'dst_oui', 'vlan_id', 'tunnel_id',
        'bidirectional_first_seen_ms', 'bidirectional_last_seen_ms',
        'src2dst_first_seen_ms', 'src2dst_last_seen_ms',
        'dst2src_first_seen_ms', 'dst2src_last_seen_ms',
        'user_agent', 'content_type', 'requested_server_name',
        'client_fingerprint', 'server_fingerprint',
        'application_name', 'application_category_name', 
        'application_is_guessed', 'application_confidence'
    ]
    
    existing_cols_to_drop = [c for c in cols_to_drop if c in df.columns]
    df.drop(columns=existing_cols_to_drop, inplace=True)
    
    # Label Encoding
    df['Label'] = df['Label'].astype(str)
    def encode_label_func(val):
        v = val.lower()
        if v in ['normal', 'benign', '0', '0.0']: return 0
        else: return 1

    df['Label'] = df['Label'].apply(encode_label_func)
    
    # Missing values
    df.fillna(0, inplace=True)
    df.replace([np.inf, -np.inf], 0, inplace=True)
    
    # Feature Engineering
    df['packet_asymmetry'] = abs(df['src2dst_packets'] - df['dst2src_packets']) / (df['bidirectional_packets'] + 1)
    df['byte_asymmetry'] = abs(df['src2dst_bytes'] - df['dst2src_bytes']) / (df['bidirectional_bytes'] + 1)
    df['bytes_per_packet'] = df['bidirectional_bytes'] / (df['bidirectional_packets'] + 1)
    df['src2dst_bpp'] = df['src2dst_bytes'] / (df['src2dst_packets'] + 1)
    df['dst2src_bpp'] = df['dst2src_bytes'] / (df['dst2src_packets'] + 1)
    df['duration_ratio'] = df['src2dst_duration_ms'] / (df['dst2src_duration_ms'] + 1)
    df['piat_variance_ratio'] = df['bidirectional_stddev_piat_ms'] / (df['bidirectional_mean_piat_ms'] + 1)
    df['ps_variance_ratio'] = df['bidirectional_stddev_ps'] / (df['bidirectional_mean_ps'] + 1)
    
    return df

def perform_feature_selection(X, y):
    print("  Feature Selection (Random Forest RFE)...")
    sample_size = min(50000, len(X))
    X_sample, _, y_sample, _ = train_test_split(X, y, train_size=sample_size, stratify=y, random_state=42)
    
    rf = RandomForestClassifier(n_estimators=50, n_jobs=-1, random_state=42)
    rfe = RFE(estimator=rf, n_features_to_select=20, step=2)
    rfe.fit(X_sample, y_sample)
    
    selected_features = X.columns[rfe.support_].tolist()
    importances = rfe.estimator_.feature_importances_
    
    return selected_features, importances

def train_isolation_forest(X_train, X_test, y_test):
    print("  Training Isolation Forest (Anomaly Detection)...")
    # Isolation Forest is unsupervised, but we can use it to find anomalies
    # It returns -1 for anomalies and 1 for normal
    iso = IsolationForest(contamination=0.1, random_state=42, n_jobs=-1)
    iso.fit(X_train)
    
    y_pred_raw = iso.predict(X_test)
    # Map 1 -> 0 (Normal), -1 -> 1 (Anomaly/MITM)
    y_pred = np.where(y_pred_raw == 1, 0, 1)
    
    print("  Isolation Forest Results:")
    print(classification_report(y_test, y_pred))
    return iso, y_pred

def train_cnn_lstm(X_train, y_train, X_val, y_val, n_features):
    print("  Training CNN+LSTM Model...")
    X_train_reshaped = X_train.reshape((X_train.shape[0], n_features, 1))
    X_val_reshaped = X_val.reshape((X_val.shape[0], n_features, 1))
    
    model = Sequential([
        Conv1D(64, kernel_size=3, activation='relu', padding='same', input_shape=(n_features, 1)),
        BatchNormalization(),
        MaxPooling1D(pool_size=2),
        Dropout(0.2),
        Conv1D(128, kernel_size=3, activation='relu', padding='same'),
        BatchNormalization(),
        MaxPooling1D(pool_size=2),
        Dropout(0.2),
        LSTM(64),
        Dropout(0.3),
        Dense(64, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy', tf.keras.metrics.AUC(name='auc')])
    
    callbacks = [
        EarlyStopping(monitor='val_auc', patience=5, restore_best_weights=True, mode='max'),
        ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3)
    ]
    
    history = model.fit(
        X_train_reshaped, y_train,
        validation_data=(X_val_reshaped, y_val),
        epochs=15, batch_size=512, callbacks=callbacks, verbose=0
    )
    return model, history

def main():
    print("=== ROBUST MITM DETECTION TRAINING PIPELINE ===")
    os.makedirs('model', exist_ok=True)
    os.makedirs('plots', exist_ok=True)
    
    df = load_data()
    df = preprocess_data(df)
    
    X = df.drop('Label', axis=1)
    y = df['Label']
    
    selected_features, importances = perform_feature_selection(X, y)
    print(f"  Selected Features: {selected_features}")
    joblib.dump(selected_features, 'model/selected_features.pkl')
    
    X = X[selected_features]
    
    # Split
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=42)
    
    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)
    joblib.dump(scaler, 'model/scaler.pkl')
    
    # SMOTE
    print("  Applying SMOTE to training data...")
    smote = SMOTE(random_state=42)
    X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)
    
    # 1. Isolation Forest
    iso_forest, y_pred_iso = train_isolation_forest(X_train_scaled, X_test_scaled, y_test)
    joblib.dump(iso_forest, 'model/iso_forest.pkl')
    
    # 2. CNN+LSTM
    nn_model, history = train_cnn_lstm(X_train_res, y_train_res, X_val_scaled, y_val, len(selected_features))
    nn_model.save('model/mitm_model.h5')
    
    # Evaluation
    print("  Evaluating Combined Robustness...")
    X_test_reshaped = X_test_scaled.reshape((X_test_scaled.shape[0], len(selected_features), 1))
    y_pred_prob_nn = nn_model.predict(X_test_reshaped).flatten()
    y_pred_nn = (y_pred_prob_nn > 0.5).astype(int)
    
    print("\nClassification Report (CNN+LSTM):")
    print(classification_report(y_test, y_pred_nn))
    
    # Save results
    results = {
        'accuracy': accuracy_score(y_test, y_pred_nn),
        'f1': f1_score(y_test, y_pred_nn),
        'precision': precision_score(y_test, y_pred_nn),
        'recall': recall_score(y_test, y_pred_nn),
        'features': selected_features
    }
    with open('model/results.json', 'w') as f:
        json.dump(results, f, indent=4)
    
    # Plots
    print("  Generating Detailed Performance Plots...")
    
    # 1. Feature Importance
    plt.figure(figsize=(10, 6))
    indices = np.argsort(importances)[::-1]
    plt.barh(range(len(selected_features)), importances[indices], align='center')
    plt.yticks(range(len(selected_features)), [selected_features[i] for i in indices])
    plt.xlabel('Importance Score')
    plt.title('Feature Importance Ranking')
    plt.savefig('plots/02_feature_importance.png')
    
    # 2. Confusion Matrix
    cm = confusion_matrix(y_test, y_pred_nn)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix (CNN+LSTM)')
    plt.savefig('plots/05_confusion_matrix.png')
    
    # 3. Training History
    plt.figure(figsize=(10, 5))
    plt.subplot(1, 2, 1)
    plt.plot(history.history['accuracy'], label='Train')
    plt.plot(history.history['val_accuracy'], label='Val')
    plt.title('Model Accuracy')
    plt.legend()
    plt.subplot(1, 2, 2)
    plt.plot(history.history['loss'], label='Train')
    plt.plot(history.history['val_loss'], label='Val')
    plt.title('Model Loss')
    plt.legend()
    plt.savefig('plots/04_training_history.png')
    
    print("=== TRAINING COMPLETE. Files in model/ and plots/ ===")

if __name__ == "__main__":
    main()
