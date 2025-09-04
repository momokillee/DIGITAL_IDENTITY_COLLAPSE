

````markdown
# Digital Identity Collapse Prototype

## Project Overview

This project is a **secure digital identity management prototype** designed to demonstrate a resilient and tamper-evident identity authentication and verification system. It integrates modern concepts of digital identities with blockchain-style logging and AI-driven fraud detection.

Traditional digital identity systems face vulnerabilities such as identity theft, weak authentication, and centralized data breaches. This project explores a new paradigm focusing on:

- **Multi-factor Authentication via OTP & Firebase Auth**
- **Tamper-Proof Audit Trails with Hash-Chain Logging**
- **Credential and Session Integrity using a Mock Blockchain Ledger**
- **AI-Based Fraud Detection analyzing login behaviour patterns**
- **Automated Security Reporting including summary charts on suspicious activities**

---

## Key Features

- **Robust Authentication:** Secure signup and login with email, password, and OTP-based multi-factor authentication.
- **Digital Credential Management:** Store and verify cryptographically hashed credentials.
- **Immutable Logging:** Chain-linked event logs stored in Firestore ensure audit-tamper resistance.
- **Mock Blockchain Verification:** Credential and session hashes are stored on a simulated blockchain ledger to prevent forgery.
- **AI Fraud Detection Module:** Analyzes user login patterns and failed attempts to generate risk scores and flag accounts requiring additional verification.
- **Automated Email Reports:** Sends security reports with detailed charts to administrators highlighting suspicious users and activities.
- **RESTful API:** Provides endpoints for user signup, login, verification, auditing, and fraud risk assessments.

---

## Technical Stack

- **Backend:** Python Flask API server  
- **Authentication:** Firebase Authentication with email/password and custom OTP system  
- **Database:** Google Firestore for storing users, logs, anomalies, ledger data, and risk assessments  
- **Security:** SHA-256 hashing, cryptographic signature hash, hash-chain logging  
- **AI Module:** Behavioral risk analysis based on recent login/anomaly history  
- **Email Alerts:** SMTP integration for real-time and periodic email notifications  
- **Charting:** Matplotlib used to generate visual security reports embedded in emails  

---

## Setup and Deployment

1. Clone repository and navigate to the project directory.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
````

3. Obtain Firebase service account credentials, save as JSON.
4. Create a `.env` file with:

   ```env
   PORT=5000
   GOOGLE_APPLICATION_CREDENTIALS=path/to/serviceAccountKey.json
   EMAIL_USER=your_email@gmail.com
   EMAIL_PASS=your_gmail_app_password
   ```
5. Enable Email/Password authentication in your Firebase console.
6. Deploy Firestore rules to secure access.
7. Create required Firestore composite indexes if prompted.
8. Run the backend:

   ```bash
   python app.py
   ```
9. Use the documented API endpoints to integrate with frontend or test workflows.

---

## Usage & Testing

* Perform signup and login flows using email and OTP.
* Monitor generated Firestore collections:
  `users`, `hash_chain_logs`, `anomalies`, `ledger_mock`, `risk_assessments`.
* View AI fraud detection risk scores returned during login verification.
* Trigger or wait for automated security report emails that include charts summarizing suspicious user activities.
* Use browser/Postman to call API endpoints for manual checks, risk history, or dashboard data.

---

## Future Enhancements

* Integrate Physical Biometrics and Multi-Device support.
* Switch from mock ledger to real blockchain infrastructure.
* Add frontend UI for identity wallet and real-time fraud dashboards.
* Implement digital signature support for transaction authenticity.
* Enhance AI engine with machine learning models on larger datasets.

---

## Acknowledgments

This prototype serves as a learning and foundational implementation to explore resilient digital identity mechanisms combining best practices in cryptography, blockchain, and AI-based security.


```


