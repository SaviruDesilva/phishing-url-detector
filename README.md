🎣 Phishing URL Detector

A high-performance Machine Learning web application built with Streamlit that identifies malicious phishing URLs in real-time. This tool helps protect users by analyzing structural patterns in links to flag security threats before they lead to data theft.
📖 Project Overview

Phishing remains the #1 entry point for cyberattacks. This application uses a hybrid approach: it analyzes URL syntax, domain metadata, and TLD reputation to classify links as "Safe" or "Phishing Attempt." It utilizes a Random Forest Classifier trained on a massive dataset of over 10,000 verified malicious and benign URLs.
Key Features

    📊 Data Dashboard: View dataset statistics and distributions (e.g., URL length vs. Phishing probability).

    🤖 AI Prediction: Real-time prediction of website status (Phishing/Safe) using machine learning.

    🛡️ Threat Analysis: Analyzes 50+ features including HTTPS status, TLD legitimacy, and obfuscated characters.

    📈 Model Performance: Visualizes the Confusion Matrix and Classification Report to demonstrate accuracy.

💻 Tech Stack

    Python 3.12

    Streamlit (Web Interface)

    Scikit-Learn (Machine Learning - Random Forest)

    Category Encoders (Target Encoding)

    Joblib (Model Serialization & Compression)

    Pandas & NumPy (Data Manipulation)

⚙️ How to Run Locally

Follow these steps to set up the project on your local machine:

    Clone the repository:
    Bash

git clone https://github.com/SaviruDesilva/phishing-url-detector.git
cd phishing-url-detector

Install dependencies:
Bash

pip install -r requirements.txt

Run the app:
Bash

    streamlit run app_phi.py

📂 Project Structure

    model.pkl — Trained Random Forest model (Compressed)

    encoder.pkl — Saved TargetEncoder for URL processing

    app_phi.py — Main Streamlit application code

    requirements.txt — List of required Python libraries

    README.md — Project documentation

🤝 Contact & Support

Developed by Saviru De Silva
