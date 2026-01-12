🎣 Phishing URL Detector

A high-performance Machine Learning web application built with Streamlit that identifies malicious phishing URLs in real-time. This tool helps protect users by analyzing structural patterns in links to flag security threats before they lead to data theft.
📖 Project Overview

Phishing remains the #1 entry point for cyberattacks. This application uses a hybrid approach: it analyzes URL syntax, domain metadata, and TLD reputation to classify links as "Safe" or "Phishing Attempt." It utilizes a Random Forest Classifier trained on a massive dataset of over 10,000 verified malicious and benign URLs to provide near-instant security assessments.
🚀 Key Features

    🕵️‍♂️ Real-time Inference: Enter any raw URL to get an immediate safety classification.

    🎲 Confidence Probability: View a percentage-based score showing how certain the AI is about the detected threat.

    🧠 Advanced Encoding: Uses TargetEncoder with smoothing to handle high-cardinality text data like Top-Level Domains (TLDs).

    🧪 Automated Feature Extraction: Automatically calculates 50+ features (URL length, subdomain counts, HTTPS status, special character ratios) from raw text strings.

    📉 Performance Analytics: Displays the Confusion Matrix and Classification Report to demonstrate model reliability.

💻 Tech Stack

    Python 3.12

    Streamlit (Web Interface)

    Scikit-Learn (Machine Learning - Random Forest)

    Category Encoders (Target Encoding for high-cardinality strings)

    Pandas & NumPy (Data Manipulation)

    Joblib (Model Serialization & Compression)

📈 Model Evaluation

To ensure the model prioritizes catching threats (Recall) while maintaining trust (Precision), it was evaluated on the following metrics:

    Accuracy: ~95%

    Critical Features: URLLength, IsHTTPS, TLDLegitimateProb, and NoOfSubDomain.

⚙️ How to Run Locally

Follow these steps to set up the detector on your local machine:

1. Clone the repository:
Bash

git clone https://github.com/SaviruDesilva/phishing-url-detector.git
cd phishing-url-detector

2. Install dependencies:
Bash

pip install -r requirements.txt

3. Run the app:
Bash

streamlit run app.py

📂 Project Structure
Plaintext

├── phi/                 # Original dataset folder
├── model.pkl            # Trained and compressed Random Forest model
├── encoder.pkl          # Saved TargetEncoder for URL string processing
├── app.py               # Main Streamlit application code
├── requirements.txt     # List of required Python libraries
└── README.md            # Project documentation

🤝 Contact & Support

Developed by Saviru De Silva
