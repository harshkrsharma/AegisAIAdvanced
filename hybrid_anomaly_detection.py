import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, Dropout
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import joblib
import os

class HybridAnomalyDetector:
    def __init__(self, feature_weights=None):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.autoencoder = None
        self.rf_model = None
        self.feature_weights = feature_weights
        self.threshold = None
        self.feature_importance = None
        
    def preprocess_data(self, df, is_training=True):
        # Convert categorical features
        categorical_features = ['Protocol', 'TCP Flags', 'Src Country', 'Dst Country', 'Direction']
        
        for feature in categorical_features:
            df[feature] = df[feature].fillna('Unknown')
            if is_training:
                # Fit the encoder on all possible values
                self.label_encoders[feature] = LabelEncoder()
                # Get all unique values for this feature
                unique_values = df[feature].unique()
                # Fit the encoder on all possible values
                self.label_encoders[feature].fit(unique_values)
                # Now transform the data
                df[feature] = self.label_encoders[feature].transform(df[feature].astype(str))
            else:
                # For test data, use the fitted encoders
                try:
                    df[feature] = self.label_encoders[feature].transform(df[feature].astype(str))
                except ValueError as e:
                    # Handle unseen labels by mapping them to a default value
                    print(f"Warning: Found unseen labels in {feature}. Mapping to default value.")
                    df[feature] = df[feature].apply(
                        lambda x: 0 if x not in self.label_encoders[feature].classes_ else x
                    )
                    df[feature] = self.label_encoders[feature].transform(df[feature].astype(str))
        
        # Extract features from IP addresses
        df['Src_IP_Class'] = df['Src IP'].apply(lambda x: x.split('.')[0])
        df['Dst_IP_Class'] = df['Dst IP'].apply(lambda x: x.split('.')[0])
        df['Is_Internal_Src'] = df['Src IP'].apply(lambda x: 1 if x.startswith(('192.168.', '10.', '172.')) else 0)
        df['Is_Internal_Dst'] = df['Dst IP'].apply(lambda x: 1 if x.startswith(('192.168.', '10.', '172.')) else 0)
        df['Is_Same_Subnet'] = (df['Src_IP_Class'] == df['Dst_IP_Class']).astype(int)
        
        # Extract features from MAC addresses
        df['Src_MAC_Vendor'] = df['Src MAC'].apply(lambda x: x.split(':')[0:3])
        df['Dst_MAC_Vendor'] = df['Dst MAC'].apply(lambda x: x.split(':')[0:3])
        df['Is_Same_Vendor'] = (df['Src_MAC_Vendor'] == df['Dst_MAC_Vendor']).astype(int)
        
        # Convert timestamp to numerical features
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        df['Hour'] = df['Timestamp'].dt.hour
        df['Minute'] = df['Timestamp'].dt.minute
        df['Second'] = df['Timestamp'].dt.second
        
        # Drop original columns after feature extraction
        df = df.drop([
            'Timestamp', 'Src IP', 'Dst IP', 'Src MAC', 'Dst MAC', 
            'Flow ID', 'Src_IP_Class', 'Dst_IP_Class',
            'Src_MAC_Vendor', 'Dst_MAC_Vendor'
        ], axis=1)
        
        # Separate features and target
        X = df.drop('Label', axis=1)
        y = df['Label']
        
        return X, y
    
    def create_autoencoder(self, input_dim):
        # Encoder
        input_layer = Input(shape=(input_dim,))
        
        # Apply feature weights if provided
        if self.feature_weights is not None:
            weighted_input = tf.keras.layers.Lambda(
                lambda x: x * self.feature_weights
            )(input_layer)
        else:
            weighted_input = input_layer
        
        encoder = Dense(128, activation='relu')(weighted_input)
        encoder = Dropout(0.2)(encoder)
        encoder = Dense(64, activation='relu')(encoder)
        encoder = Dropout(0.2)(encoder)
        encoder = Dense(32, activation='relu')(encoder)
        
        # Decoder
        decoder = Dense(64, activation='relu')(encoder)
        decoder = Dropout(0.2)(decoder)
        decoder = Dense(128, activation='relu')(decoder)
        decoder = Dropout(0.2)(decoder)
        decoder = Dense(input_dim, activation='sigmoid')(decoder)
        
        # Autoencoder
        autoencoder = Model(input_layer, decoder)
        autoencoder.compile(optimizer='adam', loss='mse')
        
        return autoencoder
    
    def train_random_forest(self, X_train, y_train):
        print("\nTraining Random Forest for feature importance...")
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(X_train, y_train)
        
        # Get feature importance
        self.feature_importance = pd.DataFrame({
            'Feature': X_train.columns,
            'Importance': rf.feature_importances_
        }).sort_values('Importance', ascending=False)
        
        print("\nTop 10 Most Important Features:")
        print(self.feature_importance.head(10))
        
        # Use feature importance as weights for autoencoder
        self.feature_weights = self.feature_importance['Importance'].values
        
        return rf
    
    def train_autoencoder(self, X_train, X_test, y_test):
        print("\nTraining Autoencoder...")
        # Scale the data
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Create and train autoencoder with feature weights
        self.autoencoder = self.create_autoencoder(X_train_scaled.shape[1])
        
        # Early stopping
        early_stopping = tf.keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=5,
            restore_best_weights=True
        )
        
        # Train the model
        history = self.autoencoder.fit(
            X_train_scaled, X_train_scaled,
            epochs=2,
            batch_size=32,
            validation_split=0.2,
            callbacks=[early_stopping],
            verbose=1
        )
        
        # Calculate reconstruction error
        X_test_pred = self.autoencoder.predict(X_test_scaled)
        mse = np.mean(np.power(X_test_scaled - X_test_pred, 2), axis=1)
        
        # Set threshold based on validation data
        self.threshold = np.percentile(mse, 95)  # Adjust based on desired sensitivity
        
        return history
    
    def predict(self, X):
        # Preprocess input data
        X_processed = X.copy()
        
        # Only extract IP and MAC features if the original columns exist
        if 'Src IP' in X_processed.columns:
            X_processed['Src_IP_Class'] = X_processed['Src IP'].apply(lambda x: x.split('.')[0])
            X_processed['Dst_IP_Class'] = X_processed['Dst IP'].apply(lambda x: x.split('.')[0])
            X_processed['Is_Internal_Src'] = X_processed['Src IP'].apply(lambda x: 1 if x.startswith(('192.168.', '10.', '172.')) else 0)
            X_processed['Is_Internal_Dst'] = X_processed['Dst IP'].apply(lambda x: 1 if x.startswith(('192.168.', '10.', '172.')) else 0)
            X_processed['Is_Same_Subnet'] = (X_processed['Src_IP_Class'] == X_processed['Dst_IP_Class']).astype(int)
        
        if 'Src MAC' in X_processed.columns:
            X_processed['Src_MAC_Vendor'] = X_processed['Src MAC'].apply(lambda x: x.split(':')[0:3])
            X_processed['Dst_MAC_Vendor'] = X_processed['Dst MAC'].apply(lambda x: x.split(':')[0:3])
            X_processed['Is_Same_Vendor'] = (X_processed['Src_MAC_Vendor'] == X_processed['Dst_MAC_Vendor']).astype(int)
        
        # Apply label encoding for categorical features
        for feature in self.categorical_features:
            X_processed[feature] = X_processed[feature].fillna('Unknown').astype(str)

            # Handle unseen labels
            X_processed[feature] = X_processed[feature].apply(
                lambda x: x if x in self.label_encoders[feature].classes_ else 'Unknown'
            )

            # Ensure 'Unknown' is in the encoder (added during training)
            X_processed[feature] = self.label_encoders[feature].transform(X_processed[feature])

        # Add time features if timestamp exists
        if 'Timestamp' in X_processed.columns:
            X_processed['Timestamp'] = pd.to_datetime(X_processed['Timestamp'])
            X_processed['Hour'] = X_processed['Timestamp'].dt.hour
            X_processed['Minute'] = X_processed['Timestamp'].dt.minute
            X_processed['Second'] = X_processed['Timestamp'].dt.second
            X_processed = X_processed.drop('Timestamp', axis=1)
        
        # Drop original columns after feature extraction if they exist
        columns_to_drop = [
            'Src IP', 'Dst IP', 'Src MAC', 'Dst MAC', 
            'Flow ID', 'Src_IP_Class', 'Dst_IP_Class',
            'Src_MAC_Vendor', 'Dst_MAC_Vendor'
        ]
        for col in columns_to_drop:
            if col in X_processed.columns:
                X_processed = X_processed.drop(col, axis=1)
        
        # Scale the data
        X_scaled = self.scaler.transform(X_processed)
        
        # Get reconstruction error
        X_pred = self.autoencoder.predict(X_scaled)
        mse = np.mean(np.power(X_scaled - X_pred, 2), axis=1)
        
        # Convert to anomaly scores (0: normal, 1: anomaly)
        predictions = (mse > self.threshold).astype(int)
        
        # Add confidence scores
        confidence_scores = mse / self.threshold
        
        return predictions, confidence_scores
    
    def evaluate(self, X_test, y_test):
        predictions, confidence_scores = self.predict(X_test)
        
        print("\nHybrid Model Results:")
        print(classification_report(y_test, predictions))
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, predictions))
        
        # Plot ROC curve
        fpr, tpr, _ = roc_curve(y_test, confidence_scores)
        roc_auc = auc(fpr, tpr)
        
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curve')
        plt.legend(loc="lower right")
        plt.savefig('roc_curve.png')
        plt.close()
        
        return {
            'classification_report': classification_report(y_test, predictions, output_dict=True),
            'confusion_matrix': confusion_matrix(y_test, predictions),
            'roc_auc': roc_auc
        }
    
    def save_model(self, path='models'):
        os.makedirs(path, exist_ok=True)
        
        # Save autoencoder
        self.autoencoder.save(os.path.join(path, 'autoencoder.h5'))
        
        # Save scaler and label encoders
        joblib.dump(self.scaler, os.path.join(path, 'scaler.joblib'))
        joblib.dump(self.label_encoders, os.path.join(path, 'label_encoders.joblib'))
        
        # Save feature importance and threshold
        np.save(os.path.join(path, 'feature_weights.npy'), self.feature_weights)
        np.save(os.path.join(path, 'threshold.npy'), self.threshold)
        
        print(f"Model saved to {path}")
    
    def load_model(self, path='models'):
        # Load autoencoder
        self.autoencoder = tf.keras.models.load_model(os.path.join(path, 'autoencoder.h5'))
        
        # Load scaler and label encoders
        self.scaler = joblib.load(os.path.join(path, 'scaler.joblib'))
        self.label_encoders = joblib.load(os.path.join(path, 'label_encoders.joblib'))
        
        # Load feature weights and threshold
        self.feature_weights = np.load(os.path.join(path, 'feature_weights.npy'))
        self.threshold = np.load(os.path.join(path, 'threshold.npy'))
        
        print(f"Model loaded from {path}")

def main():
    # Load the dataset
    print("Loading dataset...")
    df = pd.read_csv('synthetic_network_traffic_large.csv')
    
    # Split the data first
    train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)
    
    # Initialize the hybrid detector
    detector = HybridAnomalyDetector()
    
    # Preprocess training data
    print("Preprocessing training data...")
    X_train, y_train = detector.preprocess_data(train_df, is_training=True)
    
    # Preprocess test data
    print("Preprocessing test data...")
    X_test, y_test = detector.preprocess_data(test_df, is_training=False)
    
    # Train Random Forest for feature importance
    detector.train_random_forest(X_train, y_train)
    
    # Train Autoencoder with feature weights
    history = detector.train_autoencoder(X_train, X_test, y_test)
    
    # Evaluate the model
    results = detector.evaluate(X_test, y_test)
    
    # Save the model
    detector.save_model()
    
    print("\nTraining complete!")
    print(f"Final threshold: {detector.threshold:.4f}")
    print(f"ROC AUC Score: {results['roc_auc']:.4f}")

if __name__ == "__main__":
    main() 
