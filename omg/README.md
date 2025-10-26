# Phishing Simulation & Awareness Training Platform
A Flask-based web application designed to **simulate phishing campaigns** in a safe and educational environment. This project helps organizations and educators increase awareness of phishing threats by training users to recognize and properly handle suspicious emails.

## 🚩 Purpose
This platform is for **cybersecurity education** and **internal security training**. It enables administrators or trainers to create, launch, and track simulated phishing attacks while delivering in-app security awareness content.

## ✨ Features
- **Employee Registration & Login:** User authentication system for participants.
- **Learning Center:** Integrated educational module explaining phishing, attack types, and warning signs.
- **Custom Email Templates:** Create and manage HTML-based phishing templates.
- **Simulated Campaigns:** Create new phishing campaigns and send crafted emails to users.
- **Tracking & Analytics:** Embedded tracking links to monitor if and when users interact with simulated phishing emails.
- **User Management:** Organize, register, and assign users for each campaign.

## 🛠️ Technologies Used
- **Backend:** Python, Flask
- **Templates:** Jinja2, HTML5, Bootstrap CSS
- **Email:** SMTP (Flask-Mail or smtplib)
- **Frontend:** Responsive, educational content and quiz modules

## 🚀 Installation & Setup
1. **Clone the repository:**
   ```
   git clone https://github.com/<your-username>/phishing-simulation-platform.git
   cd phishing-simulation-platform
   ```

2. **Install dependencies:**
   ```
   pip install -r requirements.txt
   ```

3. **Configure email settings:**
   - Create a file called `config.py` and add your SMTP and secret key details:
     ```
     MAIL_SERVER = 'smtp.gmail.com'
     MAIL_PORT = 587
     MAIL_USE_TLS = True
     MAIL_USERNAME = 'your-training-email@domain.com'
     MAIL_PASSWORD = 'your-app-password'
     MAIL_DEFAULT_SENDER = 'your-training-email@domain.com'
     SECRET_KEY = 'your-secret-key'
     ```
   - Update credentials as needed.

4. **Run the application:**
   ```
   export FLASK_APP=app
   flask run
   ```
   The app will be available at [http://localhost:5000](http://localhost:5000).

## 📧 Email Sending (Simulation)
- The application sends emails using your configured SMTP server.
- Make sure you use an **organizational/test account** or app passwords for secure and reliable delivery.

## 🧠 Educational Content
- Users can access the Learning Center for:
  - **Phishing explanations, attack types**
  - **Best practices, real-world examples**
  - **Interactive quizzes and tips**

## 🛡️ Disclaimer
> **This platform is intended only for cybersecurity education, internal training, and awareness programs. Do not use this tool for unauthorized or malicious activity. Always obtain explicit consent from all participants before running any campaigns.**

## 🙌 Acknowledgments
- Inspired by cybersecurity awareness resources and the global fight against phishing threats.