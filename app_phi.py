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
import category_encoders as ce

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="Phishing Site Detector", page_icon="🛡️", layout="wide")

# --- 1. SMART URL CLEANER (Fixes Typos) ---
def clean_url(url):
    """Fixes common user typos like 'htp://' and adds https if missing."""
    if not url: return None
    url = url.strip()
    
    # Fix protocol typos
    if url.startswith("htp://"): url = "http://" + url[6:]
    elif url.startswith("htps://"): url = "https://" + url[7:]
    elif url.startswith("www."): url = "https://" + url
    
    # Ensure protocol exists
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    return url

# --- 2. UNIVERSAL WHITELIST ---
def is_whitelisted(url):
    try:
        extracted = tldextract.extract(url)
        domain = extracted.domain.lower()
        suffix = extracted.suffix.lower()
        
        # 1. Check if domain is valid (Must have a suffix like .com)
        if not suffix:
            return False, "Invalid Domain"

        # 2. Trusted Top-Level Domains (Gov/Edu)
        if suffix in ['gov', 'edu', 'mil']:
            return True, "Government/Educational Domain"

        # 3. Global Safe List
        trusted_domains = [
            'wikipedia', 'google', 'facebook', 'amazon', 'microsoft', 
            'github', 'youtube', 'twitter', 'instagram', 'linkedin',
            'whatsapp', 'netflix', 'stackoverflow', 'apple', 'adobe',
            'dropbox', 'wordpress', 'yahoo', 'bing', 'paypal', 'chase'
        ]
        
        if domain in trusted_domains:
            return True, "Trusted Global Domain"
            
        return False, ""
    except:
        return False, ""

# --- 3. DOMAIN AGE CHECKER (With Safety Guard) ---
def check_domain_age(url):
    try:
        extracted = tldextract.extract(url)
        
        # SAFETY GUARD: If tldextract can't find a suffix (like .com), STOP.
        # This prevents the "hanging" issue you saw.
        if not extracted.suffix:
            return None
            
        domain_name = f"{extracted.domain}.{extracted.suffix}"
        
        # Fetch WHOIS data with a timeout handling wrapper ideally, 
        # but pure python-whois doesn't support timeout easily.
        # We wrap in a broad try-except to catch hanging/failures.
        domain_info = whois.whois(domain_name)
        creation_date = domain_info.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if not creation_date:
            return None 
            
        now = datetime.now()
        age_days = (now - creation_date).days
        return age_days
    except Exception:
        # If WHOIS fails or hangs, just return None so the app continues
        return None

# --- 4. FEATURE EXTRACTION ---
def extract_features_for_model(url):
    features = {}
    
    # Basic Parsing
    extracted = tldextract.extract(url)
    features['URL'] = url
    features['Domain'] = extracted.domain
    features['TLD'] = f".{extracted.suffix}"
    features['URLLength'] = len(url)
    features['DomainLength'] = len(extracted.domain)
    features['TLDLength'] = len(extracted.suffix)
    
    features['IsDomainIP'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", extracted.domain) else 0
    features['IsHTTPS'] = 1 if url.startswith('https') else 0
    features['NoOfSubDomain'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
    
    features['NoOfLettersInURL'] = sum(c.isalpha() for c in url)
    features['LetterRatioInURL'] = features['NoOfLettersInURL'] / len(url) if len(url) > 0 else 0
    features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url)
    features['DegitRatioInURL'] = features['NoOfDegitsInURL'] / len(url) if len(url) > 0 else 0
    
    features['NoOfEqualsInURL'] = url.count('=')
    features['NoOfQMarkInURL'] = url.count('?')
    features['NoOfAmpersandInURL'] = url.count('&')
    
    special_chars = ['@', '!', '$', '%', '^', '*', '(', ')', '-', '+', '[', ']', '{', '}', ';', ':', ',', '.', '<', '>', '/', '\\', '|', '~', '`', '_']
    features['NoOfOtherSpecialCharsInURL'] = sum(1 for c in url if c in special_chars)
    features['SpacialCharRatioInURL'] = features['NoOfOtherSpecialCharsInURL'] / len(url) if len(url) > 0 else 0

    # Scraping
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=4)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            text_content = soup.get_text().lower()
            html_content = response.text
            
            features['Title'] = soup.title.string if soup.title else ""
            features['HasTitle'] = 1 if features['Title'] else 0
            features['HasFavicon'] = 1 if soup.find("link", rel=lambda x: x and 'icon' in x.lower()) else 0
            features['Robots'] = 1 
            features['IsResponsive'] = 1
            features['NoOfURLRedirect'] = len(response.history)
            features['HasDescription'] = 1 if soup.find("meta", attrs={"name": "description"}) else 0
            features['HasSocialNet'] = 1 if any(x in html_content.lower() for x in ['facebook', 'twitter', 'linkedin']) else 0
            features['HasSubmitButton'] = 1 if soup.find('input', type='submit') else 0
            features['HasHiddenFields'] = 1 if soup.find('input', type='hidden') else 0
            features['HasPasswordField'] = 1 if soup.find('input', type='password') else 0
            features['HasCopyrightInfo'] = 1 if 'copyright' in text_content or '©' in text_content else 0
            
            features['LineOfCode'] = len(html_content.split('\n'))
            features['LargestLineLength'] = max(len(line) for line in html_content.split('\n')) if html_content else 0
            
            features['NoOfImage'] = len(soup.find_all('img'))
            features['NoOfCSS'] = len(soup.find_all('link', rel='stylesheet'))
            features['NoOfJS'] = len(soup.find_all('script'))
            
            all_links = soup.find_all('a', href=True)
            self_ref = 0
            ext_ref = 0
            for link in all_links:
                href = link['href']
                if extracted.domain in href or href.startswith('/'): self_ref += 1
                else: ext_ref += 1
            features['NoOfSelfRef'] = self_ref
            features['NoOfExternalRef'] = ext_ref
            features['NoOfEmptyRef'] = 0 
            
            features['Bank'] = 1 if 'bank' in text_content else 0
            features['Pay'] = 1 if 'pay' in text_content else 0
            features['Crypto'] = 1 if 'crypto' in text_content else 0
        else:
            raise Exception("Status not 200")
    except:
        # Defaults if scraping fails
        features['Title'] = ""
        features['HasTitle'] = 0; features['LineOfCode'] = 0; features['LargestLineLength'] = 0
        features['NoOfImage'] = 0; features['NoOfCSS'] = 0; features['NoOfJS'] = 0
        features['NoOfSelfRef'] = 0; features['NoOfExternalRef'] = 0; features['HasCopyrightInfo'] = 0
        features['Bank'] = 0; features['Pay'] = 0; features['Crypto'] = 0; features['HasFavicon'] = 0
        features['Robots'] = 0; features['IsResponsive'] = 0; features['NoOfURLRedirect'] = 0
        features['HasDescription'] = 0; features['HasSocialNet'] = 0; features['HasSubmitButton'] = 0
        features['HasHiddenFields'] = 0; features['HasPasswordField'] = 0; features['NoOfEmptyRef'] = 0

    # Statistical Defaults (Needed for Model)
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

try:
    model = joblib.load('model.pkl')
    encoder = joblib.load('encoder.pkl')
except FileNotFoundError:
    st.error("⚠️ CRITICAL: 'model.pkl' or 'encoder.pkl' not found.")
    st.stop()

# --- INPUT SECTION ---
url_input = st.text_input("Enter Website URL:", placeholder="https://www.example.com")

if st.button("Check Safety"):
    if not url_input:
        st.warning("Please enter a URL")
    else:
        # 1. Clean the URL (Fix 'htp://' etc)
        cleaned_url = clean_url(url_input)
        
        st.write(f"Analyzing: `{cleaned_url}`") # Show user the corrected URL
        
        with st.status("Running Forensic Analysis...") as status:
            
            # LAYER 1: WHITELIST
            status.update(label="Checking Trust Database...", state="running")
            is_trusted, reason = is_whitelisted(cleaned_url)
            
            if is_trusted:
                status.update(label="Verified!", state="complete")
                st.balloons()
                st.success(f"✅ **SAFE SITE** ({reason})")
                st.stop()
            
            # LAYER 2: DOMAIN AGE
            status.update(label="Checking Domain Registration Age...", state="running")
            age = check_domain_age(cleaned_url)
            
            if age and age > 365:
                status.update(label="Domain is Established", state="complete")
                st.balloons()
                st.success(f"✅ **SAFE SITE** (Established Domain)")
                st.write(f"**Domain Age:** {age} days")
                st.info("Verified active for over 1 year.")
                st.stop() # Trust old domains, stop here to save time
                
            # LAYER 3: AI MODEL
            status.update(label="Scanning Code Patterns...", state="running")
            
            features = extract_features_for_model(cleaned_url)
            df_features = pd.DataFrame([features])
            
            try:
                df_encoded = encoder.transform(df_features)
                # Fix columns crash
                if hasattr(model, 'feature_names_in_'):
                    df_encoded = df_encoded.reindex(columns=model.feature_names_in_, fill_value=0)
                    
                prediction = model.predict(df_encoded)[0]
                prob = model.predict_proba(df_encoded)[0]
                
                status.update(label="Analysis Complete", state="complete")
                
                if prediction == 1: # Adjust based on your model (1=Phish usually)
                        st.error(f"🚨 **PHISHING DETECTED** (Confidence: {prob[1]*100:.2f}%)")
                        st.dataframe(df_features)
                else:
                    st.success(f"✅ **SAFE SITE** (Confidence: {prob[0]*100:.2f}%)")
                    
            except Exception as e:
                st.error(f"Model Error: {e}")
