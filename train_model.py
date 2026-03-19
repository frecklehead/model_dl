import os
import glob
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import RFE
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score, roc_curve, auc
from imblearn.over_sampling import SMOTE
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, BatchNormalization, MaxPooling1D, Dropout, LSTM, Dense
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

# Set random seed for reproducibility
np.random.seed(42)
tf.random.set_seed(42)

def main():
    print("=== STARTING MITM DETECTION PIPELINE ===")
    
    # 0. Setup Directories
    os.makedirs('model', exist_ok=True)
    os.makedirs('plots', exist_ok=True)
    
    # 1. LOAD AND MERGE ALL 5 DATASETS
    print(" Loading and Merging Datasets...")
    dataset_path = 'dataset/'
    all_files = glob.glob(os.path.join(dataset_path, "*.csv"))
    
    if not all_files:
        # Fallback to archive if dataset is empty (just in case)
        if os.path.exists('archive'):
            print("  Warning: No files in dataset/, checking archive/...")
            all_files = glob.glob(os.path.join('archive', "*.csv"))
    
    if not all_files:
        raise FileNotFoundError("No CSV files found in dataset/ or archive/")
        
    print(f"  Found {len(all_files)} files: {[os.path.basename(f) for f in all_files]}")
    
    li = []
    for filename in all_files:
        try:
            # Read CSV - minimal preprocessing here to just get the data
            df_temp = pd.read_csv(filename, index_col=None, header=0, low_memory=False)
            li.append(df_temp)
            print(f"  Loaded {os.path.basename(filename)} with shape {df_temp.shape}")
        except Exception as e:
            print(f"  Error loading {filename}: {e}")

    if not li:
        raise ValueError("No dataframes loaded.")

    df = pd.concat(li, axis=0, ignore_index=True)
    print(f"  Merged DataFrame Shape: {df.shape}")
    
    if 'Label' not in df.columns:
        # Try to find a column that looks like 'Label' (case insensitive)
        possible_labels = [c for c in df.columns if c.lower() == 'label']
        if possible_labels:
            print(f"  Renaming '{possible_labels[0]}' to 'Label'")
            df.rename(columns={possible_labels[0]: 'Label'}, inplace=True)
        else:
            raise ValueError("Label column not found!")

    print(f"Initial Label Distribution:{df['Label'].value_counts()}")

    # 2. ANALYZE EVERY COLUMN (Keep or Drop)
    print(" Analyzing and Dropping Columns...")
    
    # Define columns to drop based on hints
    # Identity, Absolute timestamps, Infrastructure, Text
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
    
    # Filter to only drop columns that actually exist
    existing_cols_to_drop = [c for c in cols_to_drop if c in df.columns]
    print(f"  Dropping {len(existing_cols_to_drop)} columns: {existing_cols_to_drop}")
    df.drop(columns=existing_cols_to_drop, inplace=True)
    
    # Explicitly ensure we kept the required ones: Protocol, ip_version, ports
    required_keep = ['protocol', 'ip_version', 'src_port', 'dst_port', 'Label']
    for col in required_keep:
        if col not in df.columns:
            print(f"  Warning: Required column '{col}' is missing!")
    
    print(f"  Shape after dropping: {df.shape}")

    # 3. LABEL ENCODING
    print(" Label Encoding...")
    # Convert Label to string just in case
    df['Label'] = df['Label'].astype(str)
    
    # Define mapping: 0 = Normal/Benign, 1 = MITM/Attack
    # Normalize text to lower case for matching
    
    def encode_label_func(val):
        v = val.lower()
        if v in ['normal', 'benign', '0', '0.0']:
            return 0
        else:
            return 1

    df['Label_Encoded'] = df['Label'].apply(encode_label_func)
    
    print("  Class mapping example:")
    print(df[['Label', 'Label_Encoded']].drop_duplicates())
    
    # Drop original label
    df.drop(columns=['Label'], inplace=True)
    df.rename(columns={'Label_Encoded': 'Label'}, inplace=True)
    
    print(f"  Class Distribution after encoding:{df['Label'].value_counts()}")

    # 4. HANDLE MISSING VALUES
    print("Handling Missing Values...")
    
    # Count missing before
    missing_before = df.isnull().sum().sum()
    print(f"  Total missing values before: {missing_before}")
    
    # Drop rows where Label is missing (should be none after encoding, but safe check)
    if df['Label'].isnull().any():
        print("  Dropping rows with missing Label...")
        df.dropna(subset=['Label'], inplace=True)
        
    # Fill numerical NaN with 0
    df.fillna(0, inplace=True)
    
    # Replace inf and -inf with 0
    df.replace([np.inf, -np.inf], 0, inplace=True)
    
    missing_after = df.isnull().sum().sum()
    print(f"  Total missing values after: {missing_after}")

    # 5. FEATURE ENGINEERING
    print("Feature Engineering...")
    # Helper to safely handle division by zero (adding +1 is standard here as per prompt instructions)
    
    # packet_asymmetry
    df['packet_asymmetry'] = abs(df['src2dst_packets'] - df['dst2src_packets']) / (df['bidirectional_packets'] + 1)
    
    # byte_asymmetry
    df['byte_asymmetry'] = abs(df['src2dst_bytes'] - df['dst2src_bytes']) / (df['bidirectional_bytes'] + 1)
    
    # bytes_per_packet
    df['bytes_per_packet'] = df['bidirectional_bytes'] / (df['bidirectional_packets'] + 1)
    
    # src2dst_bpp
    df['src2dst_bpp'] = df['src2dst_bytes'] / (df['src2dst_packets'] + 1)
    
    # dst2src_bpp
    df['dst2src_bpp'] = df['dst2src_bytes'] / (df['dst2src_packets'] + 1)
    
    # duration_ratio
    df['duration_ratio'] = df['src2dst_duration_ms'] / (df['dst2src_duration_ms'] + 1)
    
    # syn_ratio
    df['syn_ratio'] = df['bidirectional_syn_packets'] / (df['bidirectional_packets'] + 1)
    
    # rst_ratio
    df['rst_ratio'] = df['bidirectional_rst_packets'] / (df['bidirectional_packets'] + 1)
    
    # piat_variance_ratio
    df['piat_variance_ratio'] = df['bidirectional_stddev_piat_ms'] / (df['bidirectional_mean_piat_ms'] + 1)
    
    # ps_variance_ratio
    df['ps_variance_ratio'] = df['bidirectional_stddev_ps'] / (df['bidirectional_mean_ps'] + 1)
    
    print("  New features created. Explanations:")
    print("    - Asymmetry/Ratios: MITM attacks often disrupt the natural symmetry of flow traffic (e.g. requesting more than receiving in scanning/spoofing).")
    print("    - Flags (SYN/RST): High ratios can indicate scanning or connection disruption attempts common in ARP spoofing.")
    print(f"  Shape after engineering: {df.shape}")

    # 6. FEATURE SELECTION using RF-RFE
    print(" Feature Selection (RF-RFE)...")
    
    X_all = df.drop('Label', axis=1)
    y_all = df['Label']
    
    # Use a sample for speed as requested (50k rows)
    sample_size = min(50000, len(df))
    print(f"  Sampling {sample_size} rows for feature selection...")
    X_sample, _, y_sample, _ = train_test_split(X_all, y_all, train_size=sample_size, stratify=y_all, random_state=42)
    
    print("  Running RFE with RandomForestClassifier (this may take a moment)...")
    rf = RandomForestClassifier(n_jobs=-1, random_state=42)
    rfe = RFE(estimator=rf, n_features_to_select=25, step=1)
    rfe.fit(X_sample, y_sample)
    
    selected_features = X_all.columns[rfe.support_].tolist()
    print(f"  Top 25 Features Selected: {selected_features}")
    
    # Rank importance (using the estimator from RFE)
    # RFE fits the estimator on the final set, so we can access feature_importances_ if supported
    # Actually RFE.estimator_ is the fitted estimator on the selected features
    importances = rfe.estimator_.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    print("  Feature Importance Ranking (Top 10 of Selected):")
    for f in range(min(10, len(selected_features))):
        print(f"    {f+1}. {selected_features[indices[f]]} ({importances[indices[f]]:.4f})")
        
    # Save selected feature names
    joblib.dump(selected_features, 'model/selected_features.pkl')
    print("  Saved selected features to model/selected_features.pkl")
    
    # Filter dataset to selected features only (+ Label)
    df = df[selected_features + ['Label']]
    print(f"  Dataset reduced to shape: {df.shape}")

    # 9. TRAIN/VAL/TEST SPLIT
    # Note: Moving split UP before normalization/SMOTE to prevent leakage as per best practices,
    # even though prompt listed it later.
    print("Train/Val/Test Split...")
    X = df.drop('Label', axis=1)
    y = df['Label']
    
    # Split: Train (70%), Temp (30%)
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
    
    # Split Temp: Val (10% of total -> 1/3 of Temp), Test (20% of total -> 2/3 of Temp)
    # 0.3 * (1/3) = 0.1 (Val), 0.3 * (2/3) = 0.2 (Test)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=2/3, stratify=y_temp, random_state=42)
    
    print(f"  Train shape: {X_train.shape}")
    print(f"  Val shape:   {X_val.shape}")
    print(f"  Test shape:  {X_test.shape}")

    # 7. NORMALIZE using StandardScaler
    print("Normalization...")
    scaler = StandardScaler()
    
    # Fit on TRAIN only
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Transform Val and Test
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)
    
    # Save scaler
    joblib.dump(scaler, 'model/scaler.pkl')
    print("  Scaler saved to model/scaler.pkl")

    # 8. BALANCE USING SMOTE
    print("Balancing Train Data with SMOTE...")
    print(f"  Class distribution BEFORE SMOTE (Train): {y_train.value_counts()}")
    
    # Why SMOTE? MITM attacks are rare compared to normal traffic. 
    # Class imbalance causes models to bias towards the majority class (Normal).
    # SMOTE synthesizes new minority class samples.
    
    smote = SMOTE(k_neighbors=5, random_state=42)
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train_scaled, y_train)
    
    print(f"  Class distribution AFTER SMOTE (Train):{y_train_resampled.value_counts()}")

    # 10. BUILD CNN+LSTM MODEL
    print("Building CNN+LSTM Model...")
    
    # Reshape for CNN input: (samples, n_features, 1)
    n_features = X_train_resampled.shape[1]
    
    X_train_cnn = X_train_resampled.reshape((X_train_resampled.shape[0], n_features, 1))
    X_val_cnn = X_val_scaled.reshape((X_val_scaled.shape[0], n_features, 1))
    X_test_cnn = X_test_scaled.reshape((X_test_scaled.shape[0], n_features, 1))
    
    model = Sequential([
        # Conv1D Layer 1
        Conv1D(64, kernel_size=3, activation='relu', padding='same', input_shape=(n_features, 1)),
        BatchNormalization(),
        MaxPooling1D(pool_size=2),
        Dropout(0.2),
        
        # Conv1D Layer 2
        Conv1D(128, kernel_size=3, activation='relu', padding='same'),
        BatchNormalization(),
        MaxPooling1D(pool_size=2),
        Dropout(0.2),
        
        # LSTM Layer
        LSTM(64),
        Dropout(0.3),
        
        # Dense Layers
        Dense(64, activation='relu'),
        BatchNormalization(),
        Dropout(0.2),
        
        # Output Layer
        Dense(1, activation='sigmoid')
    ])
    
    optimizer = Adam(learning_rate=0.001)
    
    model.compile(optimizer=optimizer,
                  loss='binary_crossentropy',
                  metrics=['accuracy', tf.keras.metrics.Precision(name='precision'), 
                           tf.keras.metrics.Recall(name='recall'), tf.keras.metrics.AUC(name='auc')])
    
    model.summary()

    # 11. TRAIN WITH CALLBACKS
    print(" Training...")
    
    callbacks = [
        EarlyStopping(monitor='val_auc', patience=5, restore_best_weights=True, mode='max'),
        ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3, min_lr=0.00001)
    ]
    
    history = model.fit(
        X_train_cnn, y_train_resampled,
        validation_data=(X_val_cnn, y_val),
        epochs=20,
        batch_size=256,
        callbacks=callbacks,
        verbose=1
    )

    # 12. EVALUATE AND REPORT
    print(" Evaluation...")
    
    # Evaluate on Test Set
    scores = model.evaluate(X_test_cnn, y_test, verbose=0)
    print(f"  Test Accuracy:  {scores[1]:.4f}")
    print(f"  Test Precision: {scores[2]:.4f}")
    print(f"  Test Recall:    {scores[3]:.4f}")
    print(f"  Test AUC:       {scores[4]:.4f}")
    
    # Predictions
    y_pred_prob = model.predict(X_test_cnn)
    y_pred = (y_pred_prob > 0.5).astype(int)  # Standard 0.5 threshold for published metrics
    
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'MITM']))
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"  Confusion Matrix: TP={tp}, TN={tn}, FP={fp}, FN={fn}")
    
    # PLOTS
    print("  Generating plots in plots/ folder...")
    
    # 1. Accuracy Curve
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='Train Accuracy')
    plt.plot(history.history['val_accuracy'], label='Val Accuracy')
    plt.title('Model Accuracy')
    plt.ylabel('Accuracy')
    plt.xlabel('Epoch')
    plt.legend()
    plt.savefig('plots/accuracy_curve.png')
    plt.close()
    
    # 2. Loss Curve
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['loss'], label='Train Loss')
    plt.plot(history.history['val_loss'], label='Val Loss')
    plt.title('Model Loss')
    plt.ylabel('Loss')
    plt.xlabel('Epoch')
    plt.legend()
    plt.savefig('plots/loss_curve.png')
    plt.close()
    
    # 3. ROC Curve
    fpr, tpr, _ = roc_curve(y_test, y_pred_prob)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(10, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic')
    plt.legend(loc="lower right")
    plt.savefig('plots/roc_curve.png')
    plt.close()
    
    # 4. Feature Importance (Top 20 from RFE selection phase)
    # We use the 'importances' calculated in Step 6
    plt.figure(figsize=(12, 8))
    top_indices = indices[:20]
    plt.barh(range(len(top_indices)), importances[top_indices], align='center')
    plt.yticks(range(len(top_indices)), [selected_features[i] for i in top_indices])
    plt.xlabel('Feature Importance')
    plt.title('Top 20 Features (Random Forest)')
    plt.gca().invert_yaxis()
    plt.savefig('plots/feature_importance.png')
    plt.close()
    
    # 5. Confusion Matrix Heatmap
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'MITM'], yticklabels=['Normal', 'MITM'])
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.title('Confusion Matrix')
    plt.savefig('plots/confusion_matrix.png')
    plt.close()

    # 13. SAVE ALL MODEL FILES
    print("Saving Model Files...")
    model.save('model/mitm_model.h5')
    
    # Save metrics
    metrics_dict = {
        'accuracy': scores[1],
        'precision': scores[2],
        'recall': scores[3],
        'auc': scores[4],
        'f1': f1_score(y_test, y_pred)
    }
    joblib.dump(metrics_dict, 'model/model_summary.pkl')
    
    print("  All files saved successfully.")
    print("=== PIPELINE COMPLETE ===")

if __name__ == "__main__":
    main()
