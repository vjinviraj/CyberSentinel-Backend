from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
import pickle
import pandas as pd
from webscrapper import WebsiteInfoScraper
from convert_feature import extract_features_from_data

app = Flask(__name__)

CORS(app)

# Define feature weights (copied from predict_url.py)
feature_weights = {
    "HTTPS": 2.5, "AbnormalURL": 2.2, "UsingIP": 2.0, "AgeofDomain": 2.0, "DNSRecording": 1.8,
    "WebsiteForwarding": 1.7, "DisableRightClick": 1.7, "IframeRedirection": 1.6, "StatusBarCust": 1.6, "UsingPopupWindow": 1.5,
    "Symbol@": 1.5, "Redirecting//": 1.5, "PrefixSuffix-": 1.4, "SubDomains": 1.4,
    "AnchorURL": 1.3, "RequestURL": 1.3, "LinksInScriptTags": 1.3, "ServerFormHandler": 1.3,
    "StatsReport": 1.2, "GoogleIndex": 1.2, "Favicon": 1.1, "InfoEmail": 1.1, "DomainRegLen": 1.0,
    "HTTPSDomainURL": 1.0, "NonStdPort": 1.0, "LongURL": 0.9, "ShortURL": 0.9, "WebsiteTraffic": 0.8, "PageRank": 0.8,
    "LinksPointingToPage": 0.7
}

# Load model once at startup
with open("calibrated_model.pkl", "rb") as model_file:
    model = pickle.load(model_file)

def apply_feature_weights(X, weights):
    """Apply feature weights to the input data"""
    X_weighted = X.copy()
    for feature, weight in weights.items():
        if feature in X_weighted.columns:
            X_weighted[feature] = X_weighted[feature] * weight
    return X_weighted

@app.route('/analyze', methods=['POST'])
def analyze_url():
    """Analyze a URL for phishing"""
    try:
        data = request.json
        url = data.get('url')
        
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        
        # Step 1: Scrape website information
        scraper = WebsiteInfoScraper(url)
        scraped_data = scraper.collect_all_info()
        
        # Step 2: Convert scraped data to features
        features_data = extract_features_from_data(scraped_data)
        
        # Step 3: Convert features to DataFrame for prediction
        expected_features = list(feature_weights.keys())
        feature_values = [features_data.get(feat, 0) for feat in expected_features]
        input_df = pd.DataFrame([feature_values], columns=expected_features)
        
        # Step 4: Apply feature weights
        input_weighted = apply_feature_weights(input_df, feature_weights)
        
        # Step 5: Make prediction
        prediction = model.predict(input_weighted)[0]
        probabilities = model.predict_proba(input_weighted)[0]
        confidence = max(probabilities)
        
        # Step 6: Prepare response
        result = {
            "url": url,
            "prediction": int(prediction),
            "prediction_label": "Legitimate" if prediction else "Phishing",
            "confidence": round(confidence, 4),
            "phishing_probability": round(probabilities[0], 4),
            "legitimate_probability": round(probabilities[1], 4),
            "features": features_data
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    return jsonify({"status": "healthy", "service": "phishing-detection-api"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)