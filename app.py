
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
import re
import ipaddress
import json

app = Flask(__name__)
app.secret_key = "scamshield-local-secret-change-later"


def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="scam_shield"
    )


def analyze_input(text, scan_type):
    findings = []
    score = 0
    text_lower = text.lower()

    urgency_words = [
        "urgent", "immediately", "act now", "verify now",
        "account suspended", "account blocked", "limited time"
    ]

    for word in urgency_words:
        if word in text_lower:
            findings.append(f"Urgency or pressure language: '{word}'")
            score += 15

    sensitive_phrases = [
        "share otp", "send otp", "enter otp", "password",
        "bank details", "pin number", "cvv", "click here to claim"
    ]

    for phrase in sensitive_phrases:
        if phrase in text_lower:
            findings.append(
                f"Sensitive-information or suspicious request: '{phrase}'"
            )
            score += 20

    # Find URLs in the submitted text
    urls = re.findall(
        r"""https?://[^\s<>"']+|www\.[^\s<>"']+""",
        text,
        re.IGNORECASE
    )

    for raw_url in urls:
        candidate = raw_url.rstrip(".,!?;:)")
        normalized = (
            candidate
            if candidate.startswith(("http://", "https://"))
            else "http://" + candidate
        )

        parsed = urlparse(normalized)
        hostname = parsed.hostname or ""

        if parsed.scheme == "http":
            findings.append("Link uses HTTP instead of HTTPS")
            score += 10

        if "@" in parsed.netloc:
            findings.append(
                "URL contains an @ symbol, which can obscure the destination"
            )
            score += 20

        try:
            ipaddress.ip_address(hostname)
            findings.append(
                "URL uses a raw IP address instead of a domain name"
            )
            score += 20
        except ValueError:
            pass

        if hostname and hostname.count(".") >= 4:
            findings.append(
                "URL has an unusually long subdomain structure"
            )
            score += 10

        if hostname.startswith("xn--") or ".xn--" in hostname:
            findings.append(
                "URL contains an internationalized domain label"
            )
            score += 10

    if scan_type == "URL" and not urls:
        findings.append(
            "No complete HTTP/HTTPS URL was detected in the input"
        )
        score += 10

    if not findings:
        findings.append(
            "No obvious warning signs were detected by these basic checks."
        )

    score = min(score, 100)

    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return score, level, findings


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/register", methods=["POST"])
def register():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not name or not email or len(password) < 8:
        flash(
            "Enter your name, valid email and password of at least 8 characters."
        )
        return redirect(url_for("home"))

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        password_hash = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO users (name, email, password_hash)
            VALUES (%s, %s, %s)
            """,
            (name, email, password_hash)
        )

        conn.commit()
        flash("Account created successfully! Please log in.")

    except mysql.connector.IntegrityError:
        flash("This email is already registered. Please log in.")

    except mysql.connector.Error:
        app.logger.exception("Registration database error")
        flash("Database error while creating your account.")

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

    return redirect(url_for("home"))


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, name, password_hash
            FROM users
            WHERE email = %s
            """,
            (email,)
        )

        user = cursor.fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]

            return redirect(url_for("dashboard"))

        flash("Incorrect email or password.")

    except mysql.connector.Error:
        app.logger.exception("Login database error")
        flash("Database error during login.")

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

    return redirect(url_for("home"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("home"))

    return render_template(
        "dashboard.html",
        name=session["user_name"]
    )


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if "user_id" not in session:
        return redirect(url_for("home"))

    result = None

    if request.method == "POST":
        scan_type = request.form.get("scan_type", "").upper()
        input_text = request.form.get("input_text", "").strip()

        if scan_type not in ("URL", "MESSAGE"):
            flash("Choose URL or Message scanning.")
            return redirect(url_for("scan"))

        if not input_text:
            flash("Enter a URL or message to scan.")
            return redirect(url_for("scan"))

        if len(input_text) > 10000:
            flash("Input is too long. Please keep it under 10,000 characters.")
            return redirect(url_for("scan"))

        score, level, findings = analyze_input(input_text, scan_type)

        conn = None
        cursor = None

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO scan_history
                (user_id, scan_type, input_text, risk_score,
                 risk_level, findings)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    session["user_id"],
                    scan_type,
                    input_text,
                    score,
                    level,
                    json.dumps(findings)
                )
            )

            conn.commit()

        except mysql.connector.Error:
            app.logger.exception("Saving scan history failed")
            flash(
                "The scan was analyzed, but its result could not be saved."
            )

        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()

        result = {
            "scan_type": scan_type,
            "input_text": input_text,
            "risk_score": score,
            "risk_level": level,
            "findings": findings
        }

    return render_template("scanner.html", result=result)


@app.route("/history")
def history():
    if "user_id" not in session:
        return redirect(url_for("home"))

    conn = None
    cursor = None
    records = []

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, scan_type, input_text, risk_score,
                   risk_level, findings, scanned_at
            FROM scan_history
            WHERE user_id = %s
            ORDER BY scanned_at DESC
            """,
            (session["user_id"],)
        )

        records = cursor.fetchall()

        for record in records:
            try:
                record["findings_list"] = json.loads(
                    record["findings"] or "[]"
                )
            except (ValueError, TypeError):
                record["findings_list"] = []

    except mysql.connector.Error:
        app.logger.exception("Loading scan history failed")
        flash("Could not load scan history.")

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

    return render_template("history.html", records=records)


@app.route("/safety")
def safety():
    if "user_id" not in session:
        return redirect(url_for("home"))

    return render_template("safety.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
)
