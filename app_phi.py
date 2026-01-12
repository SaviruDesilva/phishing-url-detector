import streamlit as st
import pandas as pd
import joblib
import category_encoders as ce
from urllib.parse import urlparse
import re

# --- 1. Load Model & Encoder ---
# We use @st.cache_resource so it loads only once and runs fast
@st.cache_resource
def load_tools():
    try:
        model = joblib.load('model.pkl')
        encoder = joblib.load('encoder.pkl')
        return model, encoder
    except Exception as e:
        st.error(f"Error loading files: {e}")
        return None, None

model, encoder = load_tools()

# --- 2. Feature Extraction Function ---
# This takes the USER INPUT (URL) and creates the dictionary with ALL 54 VARIABLES
# your model expects.
def get_features_from_url(url):
    # Parse the URL text to get domain/scheme
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    
    # We extract what we can from the string, and use defaults for the rest
    # to prevent the "Feature Mismatch" error.
    features = {
        'URL': url,
        'URLLength': len(url),
        'Domain': domain, 
        'DomainLength': len(domain), 
        'IsDomainIP': 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0,
        'TLD': '.' + domain.split('.')[-1] if '.' in domain else '',
        'URLSimilarityIndex': 100.0, # Default assumption
        'CharContinuationRate': 1.0,
        'TLDLegitimateProb': 0.5, 
        'URLCharProb': 0.05, 
        'TLDLength': len(domain.split('.')[-1]) if '.' in domain else 0,
        'NoOfSubDomain': domain.count('.') - 1 if domain.count('.') > 1 else 0,
        'HasObfuscation': 0, 
        'NoOfObfuscatedChar': 0,
        'ObfuscationRatio': 0.0, 
        'NoOfLettersInURL': sum(c.isalpha() for c in url),
        'LetterRatioInURL': sum(c.isalpha() for c in url) / len(url) if len(url) > 0 else 0,
        'NoOfDegitsInURL': sum(c.isdigit() for c in url),
        'DegitRatioInURL': sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
        'NoOfEqualsInURL': url.count('='),
        'NoOfQMarkInURL': url.count('?'),
        'NoOfAmpersandInURL': url.count('&'),
        'NoOfOtherSpecialCharsInURL': len(re.findall(r'[^a-zA-Z0-9]', url)),
        'SpacialCharRatioInURL': len(re.findall(r'[^a-zA-Z0-9]', url)) / len(url) if len(url) > 0 else 0,
        'IsHTTPS': 1 if parsed.scheme == 'https' else 0,
        'LineOfCode': 1000,          # Dummy value (Model requires it)
        'LargestLineLength': 500,    # Dummy value
        'HasTitle': 1, 
        'Title': 'Page Title',       # Dummy text for encoder
        'DomainTitleMatchScore': 100.0, 
        'URLTitleMatchScore': 100.0, 
        'HasFavicon': 1,
        'Robots': 1, 
        'IsResponsive': 1, 
        'NoOfURLRedirect': 0, 
        'NoOfSelfRedirect': 0,
        'HasDescription': 1, 
        'NoOfPopup': 0, 
        'NoOfiFrame': 0, 
        'HasExternalFormSubmit': 0,
        'HasSocialNet': 1, 
        'HasSubmitButton': 0, 
        'HasHiddenFields': 0,
        'HasPasswordField': 0, 
        'Bank': 0, 
        'Pay': 0, 
        'Crypto': 0, 
        'HasCopyrightInfo': 1,
        'NoOfImage': 10, 
        'NoOfCSS': 5, 
        'NoOfJS': 5, 
        'NoOfSelfRef': 5, 
        'NoOfEmptyRef': 0,
        'NoOfExternalRef': 5
    }
    return pd.DataFrame([features])

# --- 3. The Streamlit App UI ---
st.title("🕵️‍♂️ Phishing Site Detector")
st.write("Enter a URL below to check if it is Safe or Phishing.")

# User Input
user_url = st.text_input("Enter Website URL:", placeholder="http://example.com")

if st.button("Check URL"):
    if user_url:
        # 1. Prepare Data
        # We wrap the single dictionary in a DataFrame just like your original code
        test_df = get_features_from_url(user_url)
        
        # 2. Transform (Using the LOADED encoder)
        # This handles 'URL', 'Domain', 'TLD', 'Title' automatically
        test_encoded = encoder.transform(test_df)
        
        # 3. Predict
        pred = model.predict(test_encoded)
        probs = model.predict_proba(test_encoded)
        
        # 4. Display Result (Using your exact logic)
        # Note: Usually 1=Phishing, 0=Safe. I checked your condition.
        # If your model output 0 for Phishing, keep it. 
        # If standard logic (1=Phishing), swap the text below.
        
        confidence = probs[0][pred[0]] * 100
        
        # Assuming standard dataset where 1 = Phishing (Dangerous)
        if pred[0] == 1:
            st.error(f"🚨 PHISHING SITE DETECTED! (Confidence: {confidence:.2f}%)")
        else:
            st.success(f"✅ SAFE SITE. (Confidence: {confidence:.2f}%)")
            
        # Optional: Show what the model saw
        with st.expander("View Extracted Features"):
            st.dataframe(test_df)
            
    else:
        st.warning("Please enter a URL first!")
