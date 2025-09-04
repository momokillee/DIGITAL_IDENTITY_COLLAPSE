# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, auth as admin_auth, firestore
from datetime import datetime, timedelta
import random, os, hashlib
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage
from collections import defaultdict
import json
import statistics
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import io
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

load_dotenv()

APP_PORT = int(os.getenv("PORT", 5000))
SERVICE_ACCOUNT = os.getenv("SERVICE_ACCOUNT_PATH",
                           os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "serviceAccountKey.json"))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

app = Flask(__name__)
CORS(app)

cred = credentials.Certificate(SERVICE_ACCOUNT)
firebase_admin.initialize_app(cred)
db = firestore.client()

otp_store = {}

# ---------- Helpers ----------
def send_email(to_email: str, subject: str, body: str) -> bool:
    if not EMAIL_USER or not EMAIL_PASS:
        print(f"[DEBUG email disabled] To: {to_email} | Subject: {subject} | Body: {body}")
        return True
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = EMAIL_USER
        msg["To"] = to_email
        msg.set_content(body)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_USER, EMAIL_PASS)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print("Email send error:", e)
        return False

def send_email_with_chart(to_email: str, subject: str, body: str, chart_image_data: bytes) -> bool:
    """Send email with embedded chart image."""
    if not EMAIL_USER or not EMAIL_PASS:
        print(f"[DEBUG email disabled] To: {to_email} | Subject: {subject} | Body: {body}")
        return True
    try:
        msg = MIMEMultipart('related')
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = to_email
        
        # Create HTML body with embedded image
        html_body = f"""
        <html>
        <body>
            <p>{body}</p>
            <br>
            <img src="cid:chart_image" alt="Security Report Chart" style="max-width: 800px;">
        </body>
        </html>
        """
        
        msg.attach(MIMEText(html_body, 'html'))
        
        # Attach chart image
        img = MIMEImage(chart_image_data)
        img.add_header('Content-ID', '<chart_image>')
        msg.attach(img)
        
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_USER, EMAIL_PASS)
            smtp.send_message(msg)
        print(f"Chart email sent to {to_email}")
        return True
    except Exception as e:
        print("Chart email send error:", e)
        return False

def generate_security_chart() -> bytes:
    """Generate security chart showing user activity and failed attempts."""
    try:
        # Get user statistics from Firestore
        user_stats = get_user_security_statistics()
        
        if not user_stats:
            # Create a placeholder chart if no data
            fig, ax = plt.subplots(figsize=(10, 6))
            ax.text(0.5, 0.5, 'No user activity data available', 
                   horizontalalignment='center', verticalalignment='center',
                   transform=ax.transAxes, fontsize=14)
            ax.set_title('Security Report - No Data Available', fontsize=16, fontweight='bold')
        else:
            # Create chart with real data
            fig, ax = plt.subplots(figsize=(12, 8))
            
            users = [stat['email'][:15] + '...' if len(stat['email']) > 15 else stat['email'] 
                    for stat in user_stats]
            total_attempts = [stat['total_attempts'] for stat in user_stats]
            failed_attempts = [stat['failed_attempts'] for stat in user_stats]
            
            # Find user with highest failed attempts for highlighting
            max_failed_idx = failed_attempts.index(max(failed_attempts)) if failed_attempts else 0
            
            x = range(len(users))
            width = 0.35
            
            # Create bars
            bars1 = ax.bar([i - width/2 for i in x], total_attempts, width, 
                          label='Total Attempts', color='lightblue', alpha=0.8)
            bars2 = ax.bar([i + width/2 for i in x], failed_attempts, width, 
                          label='Failed Attempts', color='orange', alpha=0.8)
            
            # Highlight user with most failed attempts
            if user_stats:
                bars2[max_failed_idx].set_color('red')
                bars2[max_failed_idx].set_alpha(1.0)
            
            ax.set_xlabel('Users', fontsize=12, fontweight='bold')
            ax.set_ylabel('Number of Attempts', fontsize=12, fontweight='bold')
            ax.set_title('Security Report - User Login Activity Analysis', fontsize=16, fontweight='bold')
            ax.set_xticks(x)
            ax.set_xticklabels(users, rotation=45, ha='right')
            ax.legend()
            ax.grid(axis='y', alpha=0.3)
            
            # Add suspicious user annotation
            if user_stats and failed_attempts[max_failed_idx] > 2:
                ax.annotate(f'SUSPICIOUS: {failed_attempts[max_failed_idx]} failed attempts', 
                           xy=(max_failed_idx + width/2, failed_attempts[max_failed_idx]), 
                           xytext=(max_failed_idx + width/2, failed_attempts[max_failed_idx] + max(total_attempts) * 0.1),
                           arrowprops=dict(arrowstyle='->', color='red', lw=2),
                           fontsize=10, color='red', fontweight='bold',
                           ha='center')
        
        plt.tight_layout()
        
        # Save chart to bytes
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
        img_buffer.seek(0)
        chart_bytes = img_buffer.read()
        plt.close()
        
        return chart_bytes
        
    except Exception as e:
        print(f"Error generating security chart: {e}")
        # Return empty bytes if chart generation fails
        return b''

def get_user_security_statistics() -> list:
    """Get security statistics for all users from the last 7 days."""
    try:
        since_date = datetime.utcnow() - timedelta(days=7)
        
        # Get all anomalies from last 7 days
        anomaly_logs = db.collection("anomalies")\
            .where("timestamp", ">=", since_date.isoformat())\
            .stream()
        
        # Get all hash chain logs from last 7 days
        hash_logs = db.collection("hash_chain_logs")\
            .where("timestamp", ">=", since_date)\
            .stream()
        
        user_activity = defaultdict(lambda: {'total_attempts': 0, 'failed_attempts': 0})
        
        # Process anomaly logs (these are failed attempts)
        for log in anomaly_logs:
            data = log.to_dict()
            email = data.get("email", "unknown")
            if email != "unknown":
                user_activity[email]['failed_attempts'] += 1
                user_activity[email]['total_attempts'] += 1
        
        # Process hash chain logs
        for log in hash_logs:
            data = log.to_dict()
            user_id = data.get("user_id", "unknown")
            event_type = data.get("event_type", "")
            
            if user_id != "unknown":
                user_activity[user_id]['total_attempts'] += 1
                if "fail" in event_type.lower():
                    user_activity[user_id]['failed_attempts'] += 1
        
        # Convert to list format and sort by failed attempts (descending)
        stats_list = []
        for email, stats in user_activity.items():
            stats_list.append({
                'email': email,
                'total_attempts': stats['total_attempts'],
                'failed_attempts': stats['failed_attempts']
            })
        
        # Sort by failed attempts descending, then by total attempts
        stats_list.sort(key=lambda x: (x['failed_attempts'], x['total_attempts']), reverse=True)
        
        # Limit to top 10 users for chart readability
        return stats_list[:10]
        
    except Exception as e:
        print(f"Error getting user security statistics: {e}")
        return []

def send_security_report_email():
    """Generate and send security report with chart to admin email."""
    try:
        chart_data = generate_security_chart()
        user_stats = get_user_security_statistics()
        
        # Create email body with summary
        body_lines = [
            "🔒 AUTOMATED SECURITY REPORT 🔒",
            "",
            f"Report generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"Analysis period: Last 7 days",
            "",
            "📊 SUMMARY:",
        ]
        
        if user_stats:
            total_users = len(user_stats)
            total_failed = sum(stat['failed_attempts'] for stat in user_stats)
            suspicious_users = [stat for stat in user_stats if stat['failed_attempts'] > 2]
            
            body_lines.extend([
                f"• Total active users: {total_users}",
                f"• Total failed attempts: {total_failed}",
                f"• Suspicious users (>2 failed): {len(suspicious_users)}",
                ""
            ])
            
            if suspicious_users:
                body_lines.append("⚠️ USERS REQUIRING ATTENTION:")
                for user in suspicious_users[:5]:  # Top 5 suspicious users
                    body_lines.append(f"• {user['email']}: {user['failed_attempts']} failed attempts")
                body_lines.append("")
        else:
            body_lines.append("• No user activity detected in the analysis period")
            body_lines.append("")
        
        body_lines.extend([
            "📈 Detailed activity chart is attached below.",
            "",
            "This is an automated security monitoring report.",
            "Please review and take appropriate action if necessary."
        ])
        
        email_body = "\n".join(body_lines)
        
        if chart_data:
            send_email_with_chart(
                EMAIL_USER,  # Send to admin email
                "🔒 Security Report - User Activity Analysis",
                email_body,
                chart_data
            )
        else:
            send_email(
                EMAIL_USER,
                "🔒 Security Report - User Activity Analysis", 
                email_body + "\n\n[Chart generation failed]"
            )
        
        print("Security report email sent successfully")
        return True
        
    except Exception as e:
        print(f"Error sending security report email: {e}")
        return False

def generate_otp() -> str:
    return str(random.randint(100000, 999999)).zfill(6)

def hash_credential(credential: dict) -> str:
    s = f"{credential.get('type','')}{credential.get('issuer','')}{credential.get('issue_date','')}{credential.get('expiry_date','')}{credential.get('description','')}{credential.get('credential_id','')}"
    return hashlib.sha256(s.encode()).hexdigest()

def log_anomaly(email: str, anomaly_type: str, description: str):
    try:
        db.collection("anomalies").add({
            "email": email,
            "type": anomaly_type,
            "description": description,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Trigger security report if high-risk activity detected
        if anomaly_type in ["otp", "login_failed"] and "fail" in description.lower():
            # Check if this user has multiple recent failures
            recent_failures = get_recent_failures_count(email)
            if recent_failures >= 3:  # Send report after 3+ failures
                send_security_report_email()
                
    except Exception as e:
        print("Failed to log anomaly:", e)

def get_recent_failures_count(email: str) -> int:
    """Get count of recent failures for a user in the last hour."""
    try:
        since_time = datetime.utcnow() - timedelta(hours=1)
        failures = db.collection("anomalies")\
            .where("email", "==", email)\
            .where("timestamp", ">=", since_time.isoformat())\
            .stream()
        return sum(1 for _ in failures)
    except Exception as e:
        print(f"Error counting recent failures: {e}")
        return 0

def verify_id_token(id_token: str):
    if not id_token:
        return None
    try:
        decoded = admin_auth.verify_id_token(id_token)
        return decoded
    except Exception as e:
        print("ID token verify failed:", e)
        return None

# --- MOCK BLOCKCHAIN LEDGER HELPERS ---
def store_credential_on_ledger(uid: str, credential_hash: str):
    try:
        db.collection("ledger_mock").document(f"{uid}_cred").set({
            "uid": uid,
            "type": "credential",
            "hash": credential_hash,
            "timestamp": datetime.utcnow().isoformat()
        })
        print(f"Credential hash stored on ledger for uid={uid}: {credential_hash}")
        return True
    except Exception as e:
        print("Error storing credential on ledger:", e)
        return False

def store_session_on_ledger(uid: str, session_hash: str):
    try:
        db.collection("ledger_mock").document(f"{uid}_session").set({
            "uid": uid,
            "type": "session",
            "hash": session_hash,
            "timestamp": datetime.utcnow().isoformat()
        })
        print(f"Session hash stored on ledger for uid={uid}: {session_hash}")
        return True
    except Exception as e:
        print("Error storing session on ledger:", e)
        return False

def verify_hash_on_ledger(uid: str, hash_val: str, hash_type: str):
    doc_id = f"{uid}_{hash_type}"
    try:
        doc = db.collection("ledger_mock").document(doc_id).get()
        if not doc.exists:
            return False
        return doc.to_dict().get("hash") == hash_val
    except Exception as e:
        print("Ledger verify error:", e)
        return False

# -------- Hash-Chain Logging Functions --------
def get_last_hash(user_id: str) -> str:
    try:
        logs = db.collection("hash_chain_logs")\
            .where("user_id", "==", user_id)\
            .order_by("timestamp", direction=firestore.Query.DESCENDING)\
            .limit(1).stream()
        for doc in logs:
            data = doc.to_dict()
            return data.get("hash", "")
        return ""
    except Exception as e:
        print("get_last_hash error:", e)
        return ""

def create_hash_chain_entry(user_id: str, event_type: str, event_data: str) -> dict:
    prev_hash = get_last_hash(user_id)
    timestamp = datetime.utcnow().isoformat()
    content = prev_hash + user_id + event_type + event_data + timestamp
    current_hash = hashlib.sha256(content.encode()).hexdigest()
    return {
        "user_id": user_id,
        "event_type": event_type,
        "event_data": event_data,
        "timestamp": datetime.utcnow(),
        "hash": current_hash,
        "prev_hash": prev_hash
    }

def log_hash_chain(user_id: str, event_type: str, event_data: str):
    entry = create_hash_chain_entry(user_id, event_type, event_data)
    try:
        db.collection("hash_chain_logs").add(entry)
        print(f"Hash-chain log added: {entry}")
    except Exception as e:
        print("Failed to log hash-chain entry:", e)

# -------- AI FRAUD DETECTION FUNCTIONS --------
def get_user_login_history(email: str, days_back: int = 30) -> list:
    """Get user's login history from hash chain logs and anomalies."""
    try:
        since_date = datetime.utcnow() - timedelta(days=days_back)
        
        # Get hash chain logs
        hash_logs = db.collection("hash_chain_logs")\
            .where("user_id", "==", email)\
            .where("timestamp", ">=", since_date)\
            .stream()
        
        # Get anomaly logs
        anomaly_logs = db.collection("anomalies")\
            .where("email", "==", email)\
            .where("timestamp", ">=", since_date.isoformat())\
            .stream()
        
        events = []
        
        # Process hash chain logs
        for log in hash_logs:
            data = log.to_dict()
            events.append({
                "timestamp": data.get("timestamp"),
                "type": data.get("event_type"),
                "success": "fail" not in data.get("event_type", "").lower(),
                "source": "hash_chain"
            })
        
        # Process anomaly logs
        for log in anomaly_logs:
            data = log.to_dict()
            events.append({
                "timestamp": datetime.fromisoformat(data.get("timestamp")) if isinstance(data.get("timestamp"), str) else data.get("timestamp"),
                "type": data.get("type"),
                "success": False,
                "source": "anomaly"
            })
        
        # Sort by timestamp
        events.sort(key=lambda x: x["timestamp"] if isinstance(x["timestamp"], datetime) else datetime.fromisoformat(x["timestamp"]))
        return events
        
    except Exception as e:
        print(f"Error getting login history: {e}")
        return []

def calculate_risk_score(email: str) -> dict:
    """Calculate risk score based on user behavior patterns."""
    try:
        events = get_user_login_history(email, days_back=7)  # Last 7 days
        
        if not events:
            return {"risk_score": 0, "risk_level": "low", "reasons": []}
        
        risk_factors = []
        risk_score = 0
        
        # Factor 1: Failed login attempts frequency
        failed_attempts = [e for e in events if not e["success"]]
        if len(failed_attempts) > 5:
            risk_score += 30
            risk_factors.append(f"{len(failed_attempts)} failed attempts in last 7 days")
        elif len(failed_attempts) > 2:
            risk_score += 15
            risk_factors.append(f"{len(failed_attempts)} failed attempts in last 7 days")
        
        # Factor 2: Login frequency anomaly
        login_attempts = [e for e in events if e["type"] in ["login", "otp_verify"]]
        if len(login_attempts) > 20:  # More than 20 login attempts in 7 days
            risk_score += 25
            risk_factors.append("Unusually high login frequency")
        
        # Factor 3: Time-based patterns (rapid consecutive attempts)
        rapid_attempts = 0
        for i in range(1, len(events)):
            prev_time = events[i-1]["timestamp"]
            curr_time = events[i]["timestamp"]
            
            if isinstance(prev_time, str):
                prev_time = datetime.fromisoformat(prev_time)
            if isinstance(curr_time, str):
                curr_time = datetime.fromisoformat(curr_time)
            
            time_diff = (curr_time - prev_time).total_seconds()
            if time_diff < 30:  # Less than 30 seconds between attempts
                rapid_attempts += 1
        
        if rapid_attempts > 3:
            risk_score += 20
            risk_factors.append(f"{rapid_attempts} rapid consecutive login attempts")
        
        # Factor 4: Pattern of failed OTP verifications
        failed_otps = [e for e in events if e["type"] == "otp_fail"]
        if len(failed_otps) > 3:
            risk_score += 25
            risk_factors.append(f"{len(failed_otps)} failed OTP attempts")
        
        # Determine risk level
        if risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_score": min(risk_score, 100),  # Cap at 100
            "risk_level": risk_level,
            "reasons": risk_factors,
            "total_events": len(events),
            "failed_attempts": len(failed_attempts)
        }
        
    except Exception as e:
        print(f"Error calculating risk score: {e}")
        return {"risk_score": 0, "risk_level": "low", "reasons": ["Error in calculation"]}

def log_risk_assessment(email: str, risk_data: dict):
    """Log risk assessment to Firestore."""
    try:
        db.collection("risk_assessments").add({
            "email": email,
            "risk_score": risk_data["risk_score"],
            "risk_level": risk_data["risk_level"],
            "reasons": risk_data["reasons"],
            "timestamp": datetime.utcnow().isoformat(),
            "total_events": risk_data.get("total_events", 0),
            "failed_attempts": risk_data.get("failed_attempts", 0)
        })
        print(f"Risk assessment logged for {email}: {risk_data['risk_level']} ({risk_data['risk_score']})")
    except Exception as e:
        print(f"Error logging risk assessment: {e}")

def should_require_additional_verification(risk_data: dict) -> bool:
    """Determine if additional verification is required."""
    return risk_data["risk_level"] in ["medium", "high"] and risk_data["risk_score"] >= 40

# ---------------- Signup (with OTP) ----------------
@app.route("/api/signup_start", methods=["POST"])
def signup_start():
    data = request.json or {}
    id_token = data.get("id_token")
    email = data.get("email")
    credentials_list = data.get("credentials", [])

    decoded = verify_id_token(id_token)
    if not decoded:
        return jsonify({"status":"error","message":"Invalid or missing ID token"}), 401

    uid = decoded.get("uid")
    token_email = decoded.get("email")
    if token_email and token_email != email:
        return jsonify({"status":"error","message":"Token email mismatch"}), 400

    if not uid or not email:
        return jsonify({"status":"error","message":"uid/email required"}), 400

    # prepare credentials
    for cred_item in credentials_list:
        cred_item["credential_id"] = cred_item.get("credential_id") or os.urandom(8).hex()
        cred_item["signature_hash"] = hash_credential(cred_item)

    otp = generate_otp()
    expires = (datetime.utcnow() + timedelta(minutes=10)).isoformat()

    try:
        db.collection("pending_signups").document(email).set({
            "uid": uid,
            "email": email,
            "credentials": credentials_list,
            "otp": otp,
            "expires": expires,
            "created_at": datetime.utcnow().isoformat()
        })
        send_email(email, "Your Signup OTP", f"Your signup OTP is {otp}. It expires in 10 minutes.")
        print(f"[DEBUG] Signup OTP for {email}: {otp}")
        log_hash_chain(email, "signup_start", "OTP sent for signup")
        return jsonify({"status":"success","message":"OTP sent for signup"})
    except Exception as e:
        print("signup_start error:", e)
        return jsonify({"status":"error","message":"Failed to start signup"}), 500

@app.route("/api/verify_signup_otp", methods=["POST"])
def verify_signup_otp():
    data = request.json or {}
    email = data.get("email")
    otp_input = data.get("otp")
    if not email or not otp_input:
        return jsonify({"status":"error","message":"email and otp required"}), 400

    try:
        pending_ref = db.collection("pending_signups").document(email)
        pending = pending_ref.get()
        if not pending.exists:
            return jsonify({"status":"error","message":"No pending signup found"}), 404
        pending_data = pending.to_dict()
        expires_iso = pending_data.get("expires")
        if not expires_iso:
            pending_ref.delete()
            return jsonify({"status":"error","message":"Invalid pending signup"}), 400

        expires = datetime.fromisoformat(expires_iso)
        if datetime.utcnow() > expires:
            pending_ref.delete()
            log_anomaly(email, "signup", "Signup OTP expired")
            send_email(email, "Signup OTP expired", "A signup attempt OTP expired for your email.")
            return jsonify({"status":"error","message":"OTP expired"}), 400

        if otp_input != pending_data.get("otp"):
            log_anomaly(email, "signup", "Incorrect signup OTP")
            send_email(email, "Failed signup attempt", "A failed signup OTP attempt was made on your account.")
            return jsonify({"status":"error","message":"Incorrect OTP"}), 400

        uid = pending_data.get("uid")
        credentials_list = pending_data.get("credentials", [])
        db.collection("users").document(uid).set({
            "email": email,
            "created_at": datetime.utcnow().isoformat(),
            "credentials": credentials_list
        }, merge=True)

        # Store credential hashes on the "ledger"
        for cred_item in credentials_list:
            cred_hash = cred_item.get("signature_hash")
            if cred_hash:
                store_credential_on_ledger(uid, cred_hash)

        try:
            admin_auth.update_user(uid, email_verified=True)
        except Exception as e:
            print("Warning: could not set email_verified:", e)

        pending_ref.delete()
        log_hash_chain(email, "signup_verify", "Signup OTP verified, credentials stored")

        return jsonify({"status":"success","message":"Signup verified and credentials stored", "uid": uid})
    except Exception as e:
        print("verify_signup_otp error:", e)
        return jsonify({"status":"error","message":"Failed to verify signup OTP"}), 500

# ---------------- Login (OTP) ----------------
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    id_token = data.get("id_token")
    decoded = verify_id_token(id_token)
    if not decoded:
        return jsonify({"status":"error","message":"Invalid or missing ID token"}), 401

    email = decoded.get("email")
    if not email:
        return jsonify({"status":"error","message":"No email in token"}), 400

    try:
        try:
            admin_auth.get_user_by_email(email)
        except Exception:
            log_anomaly(email, "login", "User not found during login (token present but user missing)")
        otp = generate_otp()
        otp_store[email] = {"otp": otp, "expires": datetime.utcnow() + timedelta(minutes=5)}
        send_email(email, "Your Login OTP", f"Your login OTP is {otp}. It expires in 5 minutes.")
        print(f"[DEBUG] Login OTP for {email}: {otp}")
        log_hash_chain(email, "login", "Login OTP sent")
        return jsonify({"status":"success","message":"OTP sent"})
    except Exception as e:
        print("login error:", e)
        log_anomaly(email if email else "unknown", "login", f"Error generating OTP: {e}")
        return jsonify({"status":"error","message":"Could not generate OTP"}), 500

@app.route("/api/verify_otp", methods=["POST"])
def verify_otp():
    data = request.json or {}
    email = data.get("email")
    otp_input = data.get("otp")
    if not email or not otp_input:
        return jsonify({"status":"error","message":"email and otp required"}), 400

    rec = otp_store.get(email)
    if not rec:
        log_anomaly(email, "otp", "Verify attempted without OTP sent")
        send_email(email, "Failed OTP attempt", "An OTP verification was attempted but no OTP was recently issued.")
        return jsonify({"status":"error","message":"No OTP found. Please request OTP again."}), 400

    if datetime.utcnow() > rec["expires"]:
        otp_store.pop(email, None)
        log_anomaly(email, "otp", "OTP expired")
        send_email(email, "OTP expired", "An issued OTP expired for your account.")
        return jsonify({"status":"error","message":"OTP expired"}), 400

    if otp_input == rec["otp"]:
        otp_store.pop(email, None)
        log_hash_chain(email, "otp_verify", "OTP verified successfully")
        
        # AI FRAUD DETECTION: Assess risk after successful login
        risk_data = calculate_risk_score(email)
        log_risk_assessment(email, risk_data)
        
        # Store session hash on ledger
        try:
            user = admin_auth.get_user_by_email(email)
            uid = user.uid
        except Exception:
            uid = "unknown"
        session_val = uid + str(datetime.utcnow().timestamp()) + os.urandom(8).hex()
        session_hash = hashlib.sha256(session_val.encode()).hexdigest()
        store_session_on_ledger(uid, session_hash)
        
        return jsonify({
            "status": "success",
            "message": "OTP verified", 
            "session_hash": session_hash,
            "risk_assessment": {
                "risk_level": risk_data["risk_level"],
                "risk_score": risk_data["risk_score"],
                "additional_verification_required": should_require_additional_verification(risk_data)
            }
        })
    else:
        log_anomaly(email, "otp", "Incorrect OTP entered")
        send_email(email, "Failed OTP attempt", f"A failed OTP verification was attempted on your account at {datetime.utcnow().isoformat()}. If this wasn't you, consider changing your password.")
        try:
            user = admin_auth.get_user_by_email(email)
            uid = user.uid
        except Exception:
            uid = "unknown"
        log_hash_chain(uid, "otp_fail", "Invalid OTP entered")
        return jsonify({"status":"error","message":"Incorrect OTP"}), 400

@app.route("/api/report_failed_login", methods=["POST"])
def report_failed_login():
    data = request.json or {}
    email = data.get("email")
    err_code = data.get("error_code")
    message = data.get("message", "")
    if not email:
        return jsonify({"status":"error","message":"email required"}), 400

    log_anomaly(email, "login_failed", f"{err_code} | {message}")
    send_email(email, "Failed sign-in attempt", f"A failed sign-in attempt was observed for your account. Error: {err_code}. If this wasn't you, please secure your account.")
    try:
        user = admin_auth.get_user_by_email(email)
        uid = user.uid
    except Exception:
        uid = "unknown"
    log_hash_chain(uid, "login_fail", f"{err_code} | {message}")
    return jsonify({"status":"success","message":"Reported and emailed"})

@app.route("/api/get_credentials/<uid>", methods=["GET"])
def get_credentials(uid):
    try:
        doc = db.collection("users").document(uid).get()
        if not doc.exists:
            return jsonify({"status":"error","message":"User not found"}), 404
        data = doc.to_dict()
        return jsonify({"status":"success","credentials": data.get("credentials", [])})
    except Exception as e:
        print("get_credentials error:", e)
        return jsonify({"status":"error","message": str(e)}), 500

# --- LEDGER VERIFY ENDPOINT ---
@app.route("/api/verify_ledger_hash", methods=["POST"])
def verify_ledger_hash():
    data = request.json or {}
    uid = data.get("uid")
    hash_val = data.get("hash")
    hash_type = data.get("type", "credential")  # 'credential' or 'session'
    if not uid or not hash_val:
        return jsonify({"status":"error", "message":"uid and hash required"}), 400
    verified = verify_hash_on_ledger(uid, hash_val, hash_type)
    return jsonify({"status":"success" if verified else "error", "verified": verified})

# -------- AI FRAUD DETECTION ENDPOINTS --------
@app.route("/api/assess_risk", methods=["POST"])
def assess_risk():
    """Assess user risk and return risk score with recommendations."""
    data = request.json or {}
    email = data.get("email")
    
    if not email:
        return jsonify({"status": "error", "message": "email required"}), 400
    
    try:
        risk_data = calculate_risk_score(email)
        log_risk_assessment(email, risk_data)
        
        # Determine if additional verification needed
        additional_verification = should_require_additional_verification(risk_data)
        
        response = {
            "status": "success",
            "risk_score": risk_data["risk_score"],
            "risk_level": risk_data["risk_level"],
            "reasons": risk_data["reasons"],
            "additional_verification_required": additional_verification,
            "recommendation": "Require additional verification" if additional_verification else "Normal login flow"
        }
        
        # Send alert email for high risk
        if risk_data["risk_level"] == "high":
            send_email(
                email, 
                "High Risk Activity Detected",
                f"High risk activity detected on your account. Risk score: {risk_data['risk_score']}/100. "
                f"Reasons: {', '.join(risk_data['reasons'])}. Please verify your recent login attempts."
            )
        
        return jsonify(response)
        
    except Exception as e:
        print(f"Error in risk assessment: {e}")
        return jsonify({"status": "error", "message": "Risk assessment failed"}), 500

@app.route("/api/get_risk_history/<email>", methods=["GET"])
def get_risk_history(email):
    """Get risk assessment history for a user."""
    try:
        assessments = db.collection("risk_assessments")\
            .where("email", "==", email)\
            .order_by("timestamp", direction=firestore.Query.DESCENDING)\
            .limit(10)\
            .stream()
        
        history = []
        for assessment in assessments:
            data = assessment.to_dict()
            history.append(data)
        
        return jsonify({"status": "success", "risk_history": history})
        
    except Exception as e:
        print(f"Error getting risk history: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/fraud_dashboard", methods=["GET"])
def fraud_dashboard():
    """Get dashboard data showing overall fraud detection metrics."""
    try:
        # Get recent high-risk assessments
        high_risk = db.collection("risk_assessments")\
            .where("risk_level", "==", "high")\
            .order_by("timestamp", direction=firestore.Query.DESCENDING)\
            .limit(10)\
            .stream()
        
        # Get recent anomalies
        recent_anomalies = db.collection("anomalies")\
            .order_by("timestamp", direction=firestore.Query.DESCENDING)\
            .limit(20)\
            .stream()
        
        high_risk_users = []
        for assessment in high_risk:
            data = assessment.to_dict()
            high_risk_users.append(data)
        
        anomalies = []
        for anomaly in recent_anomalies:
            data = anomaly.to_dict()
            anomalies.append(data)
        
        return jsonify({
            "status": "success",
            "high_risk_users": high_risk_users,
            "recent_anomalies": anomalies,
            "total_high_risk": len(high_risk_users),
            "total_anomalies": len(anomalies)
        })
        
    except Exception as e:
        print(f"Error getting fraud dashboard: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# -------- SECURITY REPORT ENDPOINTS --------
@app.route("/api/generate_security_report", methods=["GET"])
def generate_security_report():
    """Manually trigger security report generation and email."""
    try:
        success = send_security_report_email()
        return jsonify({
            "status": "success" if success else "error",
            "message": "Security report generated and sent" if success else "Failed to generate security report"
        })
    except Exception as e:
        print(f"Error generating security report: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=APP_PORT)
