import streamlit as st
import pandas as pd
import numpy as np
import requests
from bs4 import BeautifulSoup
import tldextract
import whois
from datetime import datetime
import joblib
import re
import os
import category_encoders as ce # Essential for your loaded encoder

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="Phishing Site Detector", page_icon="🕵️‍♂️", layout="wide")

# --- 1. UNIVERSAL WHITELIST (The "Fast Pass") ---
def is_whitelisted(url):
    try:
        extracted = tldextract.extract(url)
        domain = extracted.domain.lower()
        suffix = extracted.suffix.lower()
        
        # A list of highly trusted top-level domains could also be added (like .gov, .edu)
        if suffix in ['gov', 'edu', 'mil']:
            return True, "Government/Educational Domain"

        # Expand this list or load from a top-1m.csv file for production
        trusted_domains = [
            'wikipedia', 'google', 'facebook', 'amazon', 'microsoft', 
            'github', 'youtube', 'twitter', 'instagram', 'linkedin',
            'whatsapp', 'netflix', 'stackoverflow', 'apple', 'adobe',
            'dropbox', 'wordpress', 'yahoo', 'bing'
        ]
        
        if domain in trusted_domains:
            return True, "Trusted Global Domain"
            
        return False, ""
    except:
        return False, ""

# --- 2. DOMAIN AGE CHECKER (The "Universal" Fix) ---
def check_domain_age(url):
    try:
        extracted = tldextract.extract(url)
        domain_name = f"{extracted.domain}.{extracted.suffix}"
        
        # Fetch WHOIS data
        domain_info = whois.whois(domain_name)
        creation_date = domain_info.creation_date
        
        # Handle cases where whois returns a list of dates
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if not creation_date:
            return None 
            
        # Calculate Age in Days
        now = datetime.now()
        age_days = (now - creation_date).days
        return age_days
    except Exception as e:
        return None

# --- 3. FEATURE EXTRACTION (Matches Your Training Variables Exactly) ---
def extract_features_for_model(url):
    features = {}
    
    # 3.1 Lexical / URL Features
    extracted = tldextract.extract(url)
    features['URL'] = url
    features['Domain'] = extracted.domain
    features['TLD'] = f".{extracted.suffix}"
    features['URLLength'] = len(url)
    features['DomainLength'] = len(extracted.domain)
    features['TLDLength'] = len(extracted.suffix)
    
    # Regex Checks
    features['IsDomainIP'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", extracted.domain) else 0
    features['IsHTTPS'] = 1 if url.startswith('https') else 0
    features['NoOfSubDomain'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
    
    # Character Counts & Ratios
    features['NoOfLettersInURL'] = sum(c.isalpha() for c in url)
    features['LetterRatioInURL'] = features['NoOfLettersInURL'] / len(url) if len(url) > 0 else 0
    
    # NOTE: Keeping your typos ('Degit', 'Spacial') to match the model
    features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url)
    features['DegitRatioInURL'] = features['NoOfDegitsInURL'] / len(url) if len(url) > 0 else 0
    
    features['NoOfEqualsInURL'] = url.count('=')
    features['NoOfQMarkInURL'] = url.count('?')
    features['NoOfAmpersandInURL'] = url.count('&')
    
    special_chars = ['@', '!', '$', '%', '^', '*', '(', ')', '-', '+', '[', ']', '{', '}', ';', ':', ',', '.', '<', '>', '/', '\\', '|', '~', '`', '_']
    features['NoOfOtherSpecialCharsInURL'] = sum(1 for c in url if c in special_chars)
    features['SpacialCharRatioInURL'] = features['NoOfOtherSpecialCharsInURL'] / len(url) if len(url) > 0 else 0

    # 3.2 Content Scraping Features
    try:
        # User-Agent prevents 403 errors on safe sites
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=4)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            text_content = soup.get_text().lower()
            html_content = response.text
            
            # Extract
            features['Title'] = soup.title.string if soup.title else ""
            features['HasTitle'] = 1 if features['Title'] else 0
            features['HasFavicon'] = 1 if soup.find("link", rel=lambda x: x and 'icon' in x.lower()) else 0
            features['Robots'] = 1 # Assume true for live sites
            features['IsResponsive'] = 1
            features['NoOfURLRedirect'] = len(response.history)
            features['HasDescription'] = 1 if soup.find("meta", attrs={"name": "description"}) else 0
            features['HasSocialNet'] = 1 if any(x in html_content.lower() for x in ['facebook', 'twitter', 'linkedin']) else 0
            features['HasSubmitButton'] = 1 if soup.find('input', type='submit') else 0
            features['HasHiddenFields'] = 1 if soup.find('input', type='hidden') else 0
            features['HasPasswordField'] = 1 if soup.find('input', type='password') else 0
            features['HasCopyrightInfo'] = 1 if 'copyright' in text_content or '©' in text_content else 0
            
            # Code Metrics
            features['LineOfCode'] = len(html_content.split('\n'))
            features['LargestLineLength'] = max(len(line) for line in html_content.split('\n'))
            
            # Counts
            features['NoOfImage'] = len(soup.find_all('img'))
            features['NoOfCSS'] = len(soup.find_all('link', rel='stylesheet'))
            features['NoOfJS'] = len(soup.find_all('script'))
            
            # Reference Analysis
            all_links = soup.find_all('a', href=True)
            self_ref = 0
            ext_ref = 0
            for link in all_links:
                href = link['href']
                if extracted.domain in href or href.startswith('/'):
                    self_ref += 1
                else:
                    ext_ref += 1
            features['NoOfSelfRef'] = self_ref
            features['NoOfExternalRef'] = ext_ref
            features['NoOfEmptyRef'] = 0 # Simplified
            
            # Sensitive words
            features['Bank'] = 1 if 'bank' in text_content else 0
            features['Pay'] = 1 if 'pay' in text_content else 0
            features['Crypto'] = 1 if 'crypto' in text_content else 0
            
        else:
            # Page exists but blocked/error
            raise Exception("Status not 200")
            
    except:
        # If scraping fails, set neutral defaults
        features['Title'] = ""
        features['HasTitle'] = 0
        features['LineOfCode'] = 0
        features['LargestLineLength'] = 0
        features['NoOfImage'] = 0
        features['NoOfCSS'] = 0
        features['NoOfJS'] = 0
        features['NoOfSelfRef'] = 0
        features['NoOfExternalRef'] = 0
        features['HasCopyrightInfo'] = 0
        features['Bank'] = 0; features['Pay'] = 0; features['Crypto'] = 0
        features['HasFavicon'] = 0; features['Robots'] = 0; features['IsResponsive'] = 0
        features['NoOfURLRedirect'] = 0; features['HasDescription'] = 0; features['HasSocialNet'] = 0
        features['HasSubmitButton'] = 0; features['HasHiddenFields'] = 0; features['HasPasswordField'] = 0
        features['NoOfEmptyRef'] = 0

    # 3.3 Statistical/Probability Features (Hard to calc live, using safe defaults)
    # These prevent the model from crashing due to missing columns
    defaults = {
        'URLSimilarityIndex': 50.0, 'CharContinuationRate': 0.5, 'TLDLegitimateProb': 0.5, 
        'URLCharProb': 0.5, 'HasObfuscation': 0, 'NoOfObfuscatedChar': 0, 'ObfuscationRatio': 0.0,
        'DomainTitleMatchScore': 50.0, 'URLTitleMatchScore': 50.0, 'NoOfSelfRedirect': 0,
        'NoOfPopup': 0, 'NoOfiFrame': 0, 'HasExternalFormSubmit': 0
    }
    for k, v in defaults.items():
        features[k] = v

    return features

# --- MAIN APP UI ---

st.title("🕵️‍♂️ Advanced Phishing Detector")
st.markdown("---")

# Load Models
try:
    model = joblib.load('model.pkl')
    encoder = joblib.load('encoder.pkl')
except FileNotFoundError:
    st.error("⚠️ CRITICAL: 'model.pkl' or 'encoder.pkl' not found.")
    st.stop()

url_input = st.text_input("Enter Website URL:", placeholder="https://www.example.com")

if st.button("Check Safety"):
    if not url_input:
        st.warning("Please enter a URL")
    else:
        # Add protocol if missing
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'https://' + url_input
            
        with st.status("Running Forensic Analysis...") as status:
            
            # --- LAYER 1: WHITELIST ---
            status.update(label="Checking Global Trust Databases...", state="running")
            is_trusted, reason = is_whitelisted(url_input)
            
            if is_trusted:
                status.update(label="Verified!", state="complete")
                st.balloons()
                st.success(f"✅ **SAFE SITE** ({reason})")
                st.info("This domain is on the global whitelist of verified safe organizations.")
            
            else:
                # --- LAYER 2: DOMAIN AGE ---
                status.update(label="Checking Domain Registration Age...", state="running")
                age = check_domain_age(url_input)
                
                if age and age > 365:
                    status.update(label="Domain is Established", state="complete")
                    st.balloons()
                    st.success(f"✅ **SAFE SITE** (Established Domain)")
                    st.write(f"**Domain Age:** {age} days")
                    st.info("This domain has been active for over 1 year. Phishing sites typically last less than 1 month.")
                
                else:
                    # --- LAYER 3: AI MODEL ---
                    status.update(label="Analyzing Code Patterns with AI...", state="running")
                    
                    # 1. Extract Features
                    features = extract_features_for_model(url_input)
                    df_features = pd.DataFrame([features])
                    
                    # 2. Encode (Transform Categorical Data)
                    try:
                        # Ensure columns are in correct order for encoder
                        df_encoded = encoder.transform(df_features)
                    except Exception as e:
                        st.error(f"Encoding Error: {e}")
                        st.stop()
                    
                    # 3. Predict
                    prediction = model.predict(df_encoded)[0]
                    prob = model.predict_proba(df_encoded)[0]
                    
                    status.update(label="Analysis Complete", state="complete")
                    
                    if prediction == 0: # Assuming 0 is Phishing (check your label mapping!)
                        st.error(f"🚨 **PHISHING DETECTED** (Confidence: {prob[0]*100:.2f}%)")
                        st.write("Reasoning: This is a new site with suspicious code patterns.")
                        
                        with st.expander("Technical Details"):
                            st.write(f"**Domain Age:** {age if age else 'Unknown (New)'} days")
                            st.dataframe(df_features)
                    else:
                        st.success(f"✅ **SAFE SITE** (Confidence: {prob[1]*100:.2f}%)")
