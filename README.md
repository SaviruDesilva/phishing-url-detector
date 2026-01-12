# 🕵️‍♂️ Advanced Phishing Site Detector

A **Streamlit-based web application** that detects whether a given website is **SAFE or PHISHING** using a **multi-layer security pipeline** combining:

* URL sanitization
* Domain trust & whitelist checks
* WHOIS domain-age verification
* HTML & content-based feature extraction
* A trained **Machine Learning model** (loaded via `joblib`)

This project is designed for **real-time phishing detection** with strong fail-safes to avoid app freezing, invalid URLs, or network errors.

---

## 🚀 Features

### 🔹 Smart URL Cleaner

Automatically fixes common user mistakes:

* `htp://` → `http://`
* `htps://` → `https://`
* Missing protocol → adds `https://`

### 🔹 Universal Whitelist Layer

Immediately marks sites as **SAFE** if they belong to:

* Government / Educational domains (`.gov`, `.edu`, `.mil`)
* Trusted global platforms (Google, GitHub, Amazon, Facebook, etc.)

This improves speed and reduces false positives.

### 🔹 Domain Age Verification

* Uses WHOIS data to check domain creation date
* Domains **older than 1 year** are automatically trusted
* Includes safety guards to prevent WHOIS hangs or crashes

### 🔹 Deep Feature Extraction

Extracts **URL-level and webpage-level features**, including:

* URL length, digit & character ratios
* Subdomain & TLD analysis
* HTTPS detection
* HTML structure analysis (images, scripts, CSS, forms)
* Security-sensitive elements (password fields, hidden inputs)
* Keyword detection (bank, pay, crypto)
* Internal vs external link analysis

If scraping fails, safe default values are applied.

### 🔹 Machine Learning Detection

* Uses a **pre-trained ML model** (`model.pkl`)
* Uses a **saved encoder** (`encoder.pkl`) for categorical features
* Predicts:

  * `SAFE`
  * `PHISHING`
* Displays confidence score using `predict_proba`

---

## 🧠 Detection Pipeline

```
User URL
   ↓
URL Cleaning
   ↓
Whitelist Check
   ↓
Domain Age Check
   ↓
Feature Extraction
   ↓
Encoder Transformation
   ↓
ML Model Prediction
```

---

## 🛠️ Tech Stack

* **Python 3.10+**
* **Streamlit** – Web UI
* **Scikit-learn** – ML model
* **Joblib** – Model persistence
* **Requests** – HTTP fetching
* **BeautifulSoup (bs4)** – HTML parsing
* **tldextract** – Domain parsing
* **python-whois** – Domain age checking
* **category-encoders** – Feature encoding

---

## 📦 Installation

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/your-username/phishing-site-detector.git
cd phishing-site-detector
```

### 2️⃣ Create Virtual Environment (Recommended)

```bash
python -m venv env
source env/bin/activate   # Linux/Mac
env\Scripts\activate      # Windows
```

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the App

```bash
streamlit run app_phi.py
```

Then open your browser at:

```
http://localhost:8501
```

---

## 📁 Project Structure

```
├── app_phi.py                # Main Streamlit application
├── model.pkl             # Trained ML model
├── encoder.pkl           # Feature encoder
├── requirements.txt      # Dependencies
├── README.md             # Project documentation
```

---

## ⚠️ Important Notes

* `model.pkl` and `encoder.pkl` **must exist** in the root directory
* WHOIS lookups may fail for some domains — this is handled safely
* The app **never crashes** on invalid or unreachable URLs

---

## 🎯 Use Cases

* Cybersecurity demonstrations
* Academic & ML projects
* Phishing awareness tools
* SOC / Blue Team prototypes

---

## 🔒 Disclaimer

This tool is for **educational and defensive security purposes only**.
Do **NOT** use it for illegal activities or unauthorized scanning.

---

## 👤 Author

**Saviru Desilva**


---
