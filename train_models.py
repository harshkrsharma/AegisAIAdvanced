import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, Dropout
import matplotlib.pyplot as plt
import seaborn as sns

def preprocess_data(df):
    # Convert categorical features
    categorical_features = ['Protocol', 'TCP Flags', 'Src Country', 'Dst Country', 'Direction']
    label_encoders = {}
    
    for feature in categorical_features:
        label_encoders[feature] = LabelEncoder()
        df[feature] = label_encoders[feature].fit_transform(df[feature].astype(str))
    
    # Convert timestamp to numerical features
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    df['Hour'] = df['Timestamp'].dt.hour
    df['Minute'] = df['Timestamp'].dt.minute
    df['Second'] = df['Timestamp'].dt.second
    
    # Drop unnecessary columns
    df = df.drop(['Timestamp', 'Src IP', 'Dst IP', 'Src MAC', 'Dst MAC', 'Flow ID'], axis=1)
    
    # Separate features and target
    X = df.drop('Label', axis=1)
    y = df['Label']
    
    return X, y, label_encoders

def train_isolation_forest(X_train, X_test, y_test):
    print("\nTraining Isolation Forest...")
    iso_forest = IsolationForest(contamination=0.2, random_state=42)
    iso_forest.fit(X_train)
    
    # Predict anomalies (1 for normal, -1 for anomalies)
    y_pred = iso_forest.predict(X_test)
    y_pred = [1 if x == -1 else 0 for x in y_pred]  # Convert to 0/1 format
    
    print("\nIsolation Forest Results:")
    print(classification_report(y_test, y_pred))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    return iso_forest

def train_random_forest(X_train, X_test, y_train, y_test):
    print("\nTraining Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    
    y_pred = rf.predict(X_test)
    
    print("\nRandom Forest Results:")
    print(classification_report(y_test, y_pred))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'Feature': X_train.columns,
        'Importance': rf.feature_importances_
    }).sort_values('Importance', ascending=False)
    
    print("\nTop 10 Most Important Features:")
    print(feature_importance.head(10))
    
    return rf

def create_autoencoder(input_dim):
    # Encoder
    input_layer = Input(shape=(input_dim,))
    encoder = Dense(64, activation='relu')(input_layer)
    encoder = Dropout(0.2)(encoder)
    encoder = Dense(32, activation='relu')(encoder)
    encoder = Dropout(0.2)(encoder)
    encoder = Dense(16, activation='relu')(encoder)
    
    # Decoder
    decoder = Dense(32, activation='relu')(encoder)
    decoder = Dropout(0.2)(decoder)
    decoder = Dense(64, activation='relu')(decoder)
    decoder = Dropout(0.2)(decoder)
    decoder = Dense(input_dim, activation='sigmoid')(decoder)
    
    # Autoencoder
    autoencoder = Model(input_layer, decoder)
    autoencoder.compile(optimizer='adam', loss='mse')
    
    return autoencoder

def train_autoencoder(X_train, X_test, y_test):
    print("\nTraining Autoencoder...")
    # Scale the data
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Create and train autoencoder
    autoencoder = create_autoencoder(X_train_scaled.shape[1])
    autoencoder.fit(X_train_scaled, X_train_scaled,
                   epochs=10,
                   batch_size=32,
                   validation_split=0.2,
                   verbose=0)
    
    # Calculate reconstruction error
    X_test_pred = autoencoder.predict(X_test_scaled)
    mse = np.mean(np.power(X_test_scaled - X_test_pred, 2), axis=1)
    
    # Convert MSE to anomaly scores (higher MSE = more likely anomaly)
    threshold = np.percentile(mse, 80)  # Adjust threshold as needed
    y_pred = [1 if x > threshold else 0 for x in mse]
    
    print("\nAutoencoder Results:")
    print(classification_report(y_test, y_pred))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    return autoencoder, scaler

def main():
    # Load the dataset
    df = pd.read_csv('synthetic_network_traffic_large.csv')
    
    # Preprocess the data
    X, y, label_encoders = preprocess_data(df)
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Scale the data for models that need it
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train and evaluate models
    iso_forest = train_isolation_forest(X_train_scaled, X_test_scaled, y_test)
    rf = train_random_forest(X_train, X_test, y_train, y_test)
    autoencoder, autoencoder_scaler = train_autoencoder(X_train, X_test, y_test)
    
    print("\nModel Selection Recommendation:")
    print("1. Use Random Forest if you need interpretability and feature importance")
    print("2. Use Isolation Forest if you need fast training and detection of point anomalies")
    print("3. Use Autoencoder if you need to detect complex patterns and novel anomalies")

if __name__ == "__main__":
    main() 