import os
import secrets
from datetime import datetime

import qrcode
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from sqlalchemy import text, inspect

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "storage", "private")
QR_DIR = os.path.join(BASE_DIR, "storage", "qr")
LOGO_DIR = os.path.join(BASE_DIR, "storage", "bank_logos")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(QR_DIR, exist_ok=True)
os.makedirs(LOGO_DIR, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "replace-this-secret-key")
database_url = os.getenv("DATABASE_URL")
if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "verification.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

ALLOWED_EXTENSIONS = {"pdf"}
ALLOWED_LOGO_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "svg"}
CURRENCIES = [
    ("BDT", "BDT — Bangladeshi Taka"),
    ("USD", "USD — US Dollar"),
    ("MYR", "MYR — Malaysian Ringgit"),
    ("GBP", "GBP — British Pound"),
    ("EUR", "EUR — Euro"),
    ("SGD", "SGD — Singapore Dollar"),
    ("AUD", "AUD — Australian Dollar"),
    ("CAD", "CAD — Canadian Dollar"),
    ("AED", "AED — UAE Dirham"),
    ("SAR", "SAR — Saudi Riyal"),
]


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def allowed_logo(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_LOGO_EXTENSIONS


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Bank(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    address = db.Column(db.String(500))
    website = db.Column(db.String(500))
    logo_filename = db.Column(db.String(255))
    status = db.Column(db.String(30), default="active", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    records = db.relationship("VerificationRecord", back_populates="bank")


class VerificationRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(80), unique=True, nullable=False, index=True)
    bank_id = db.Column(db.Integer, db.ForeignKey("bank.id"), nullable=True, index=True)
    account_name = db.Column(db.String(255), nullable=False)
    account_number = db.Column(db.String(100))
    account_holder_name = db.Column(db.String(255))
    opening_balance = db.Column(db.String(100))
    closing_balance = db.Column(db.String(100))
    report_generation_date = db.Column(db.String(100))
    statement_start_date = db.Column(db.String(100))
    statement_end_date = db.Column(db.String(100))
    currency = db.Column(db.String(30))
    custom_message = db.Column(db.Text)
    status = db.Column(db.String(30), default="active")
    original_filename = db.Column(db.String(255))
    stored_filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    bank = db.relationship("Bank", back_populates="records")


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    record_id = db.Column(db.Integer)
    action = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def audit(record_id, action):
    db.session.add(AuditLog(record_id=record_id, action=action,
                            ip_address=request.headers.get("X-Forwarded-For", request.remote_addr)))
    db.session.commit()


def generate_code():
    while True:
        code = "DOC-" + secrets.token_hex(7).upper()
        if not VerificationRecord.query.filter_by(code=code).first():
            return code


def create_qr(record):
    verify_url = url_for("verify", code=record.code, _external=True)
    img = qrcode.make(verify_url)
    path = os.path.join(QR_DIR, record.code + ".png")
    img.save(path)
    return path


@app.context_processor
def inject_globals():
    return {
        "brand_name": os.getenv("BRAND_NAME", "Universal Verification Portal"),
        "brand_subtitle": os.getenv("BRAND_SUBTITLE", "Secure Document Verification"),
        "currencies": CURRENCIES,
    }


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    query = request.args.get("q", "").strip()
    if query:
        records = VerificationRecord.query.outerjoin(Bank).filter(
            db.or_(
                VerificationRecord.code.ilike(f"%{query}%"),
                VerificationRecord.account_name.ilike(f"%{query}%"),
                VerificationRecord.account_holder_name.ilike(f"%{query}%"),
                Bank.name.ilike(f"%{query}%"),
            )
        ).order_by(VerificationRecord.id.desc()).all()
    else:
        records = VerificationRecord.query.order_by(VerificationRecord.id.desc()).all()
    return render_template("dashboard.html", records=records, query=query)


@app.route("/banks")
@login_required
def banks():
    bank_list = Bank.query.order_by(Bank.name.asc()).all()
    return render_template("banks.html", banks=bank_list)


@app.route("/banks/new", methods=["GET", "POST"])
@login_required
def create_bank():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        address = request.form.get("address", "").strip()
        website = request.form.get("website", "").strip()
        if not name:
            flash("Bank/institution name is required.", "danger")
            return redirect(url_for("create_bank"))
        if Bank.query.filter(db.func.lower(Bank.name) == name.lower()).first():
            flash("A bank/institution with this name already exists.", "danger")
            return redirect(url_for("create_bank"))

        logo_filename = None
        logo = request.files.get("logo")
        if logo and logo.filename:
            if not allowed_logo(logo.filename):
                flash("Logo must be PNG, JPG, JPEG, WEBP, or SVG.", "danger")
                return redirect(url_for("create_bank"))
            ext = logo.filename.rsplit(".", 1)[1].lower()
            logo_filename = secrets.token_hex(16) + "." + ext
            logo.save(os.path.join(LOGO_DIR, logo_filename))

        db.session.add(Bank(name=name, address=address, website=website,
                            logo_filename=logo_filename, status="active"))
        db.session.commit()
        flash("Bank/institution added successfully.", "success")
        return redirect(url_for("banks"))
    return render_template("bank_form.html", bank=None, page_title="Add Bank / Institution")


@app.route("/banks/<int:bank_id>/edit", methods=["GET", "POST"])
@login_required
def edit_bank(bank_id):
    bank = db.get_or_404(Bank, bank_id)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Bank/institution name is required.", "danger")
            return redirect(url_for("edit_bank", bank_id=bank.id))
        duplicate = Bank.query.filter(db.func.lower(Bank.name) == name.lower(), Bank.id != bank.id).first()
        if duplicate:
            flash("Another bank/institution already uses this name.", "danger")
            return redirect(url_for("edit_bank", bank_id=bank.id))
        bank.name = name
        bank.address = request.form.get("address", "").strip()
        bank.website = request.form.get("website", "").strip()
        bank.status = "active" if request.form.get("status") == "active" else "inactive"

        logo = request.files.get("logo")
        if logo and logo.filename:
            if not allowed_logo(logo.filename):
                flash("Logo must be PNG, JPG, JPEG, WEBP, or SVG.", "danger")
                return redirect(url_for("edit_bank", bank_id=bank.id))
            if bank.logo_filename:
                old = os.path.join(LOGO_DIR, bank.logo_filename)
                if os.path.exists(old):
                    os.remove(old)
            ext = logo.filename.rsplit(".", 1)[1].lower()
            bank.logo_filename = secrets.token_hex(16) + "." + ext
            logo.save(os.path.join(LOGO_DIR, bank.logo_filename))
        db.session.commit()
        flash("Bank/institution updated.", "success")
        return redirect(url_for("banks"))
    return render_template("bank_form.html", bank=bank, page_title="Edit Bank / Institution")


@app.route("/banks/<int:bank_id>/toggle", methods=["POST"])
@login_required
def toggle_bank(bank_id):
    bank = db.get_or_404(Bank, bank_id)
    bank.status = "inactive" if bank.status == "active" else "active"
    db.session.commit()
    flash(f"{bank.name} is now {bank.status}.", "success")
    return redirect(url_for("banks"))


@app.route("/bank-logo/<int:bank_id>")
def bank_logo(bank_id):
    bank = db.get_or_404(Bank, bank_id)
    if not bank.logo_filename:
        abort(404)
    path = os.path.join(LOGO_DIR, bank.logo_filename)
    if not os.path.exists(path):
        abort(404)
    return send_file(path)


@app.route("/records/new", methods=["GET", "POST"])
@login_required
def create_record():
    active_banks = Bank.query.filter_by(status="active").order_by(Bank.name.asc()).all()
    if request.method == "POST":
        account_name = request.form.get("account_name", "").strip()
        bank_id = request.form.get("bank_id", type=int)
        bank = db.session.get(Bank, bank_id) if bank_id else None
        if not account_name:
            flash("Account name is required.", "danger")
            return redirect(url_for("create_record"))
        if not bank or bank.status != "active":
            flash("Please select an active bank/institution.", "danger")
            return redirect(url_for("create_record"))

        file = request.files.get("statement_file")
        stored_filename = None
        original_filename = None
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Only PDF files are allowed.", "danger")
                return redirect(url_for("create_record"))
            original_filename = secure_filename(file.filename)
            stored_filename = secrets.token_hex(20) + ".pdf"
            file.save(os.path.join(UPLOAD_DIR, stored_filename))

        record = VerificationRecord(
            code=generate_code(), bank_id=bank.id, account_name=account_name,
            account_number=request.form.get("account_number", "").strip(),
            account_holder_name=request.form.get("account_holder_name", "").strip(),
            opening_balance=request.form.get("opening_balance", "").strip(),
            closing_balance=request.form.get("closing_balance", "").strip(),
            report_generation_date=request.form.get("report_generation_date", "").strip(),
            statement_start_date=request.form.get("statement_start_date", "").strip(),
            statement_end_date=request.form.get("statement_end_date", "").strip(),
            currency=request.form.get("currency", "").strip(),
            custom_message=request.form.get("custom_message", "").strip(),
            original_filename=original_filename, stored_filename=stored_filename, status="active"
        )
        db.session.add(record)
        db.session.commit()
        create_qr(record)
        audit(record.id, "created")
        flash("Verification record created successfully.", "success")
        return redirect(url_for("record_detail", record_id=record.id))
    return render_template("record_form.html", record=None, banks=active_banks, page_title="Create Verification")


@app.route("/records/<int:record_id>/edit", methods=["GET", "POST"])
@login_required
def edit_record(record_id):
    record = db.get_or_404(VerificationRecord, record_id)
    active_banks = Bank.query.filter_by(status="active").order_by(Bank.name.asc()).all()
    if request.method == "POST":
        bank_id = request.form.get("bank_id", type=int)
        bank = db.session.get(Bank, bank_id) if bank_id else None
        if not bank or bank.status != "active":
            flash("Please select an active bank/institution.", "danger")
            return redirect(url_for("edit_record", record_id=record.id))
        record.bank_id = bank.id
        record.account_name = request.form.get("account_name", "").strip()
        record.account_number = request.form.get("account_number", "").strip()
        record.account_holder_name = request.form.get("account_holder_name", "").strip()
        record.opening_balance = request.form.get("opening_balance", "").strip()
        record.closing_balance = request.form.get("closing_balance", "").strip()
        record.report_generation_date = request.form.get("report_generation_date", "").strip()
        record.statement_start_date = request.form.get("statement_start_date", "").strip()
        record.statement_end_date = request.form.get("statement_end_date", "").strip()
        record.currency = request.form.get("currency", "").strip()
        record.custom_message = request.form.get("custom_message", "").strip()

        file = request.files.get("statement_file")
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Only PDF files are allowed.", "danger")
                return redirect(url_for("edit_record", record_id=record.id))
            if record.stored_filename:
                old_path = os.path.join(UPLOAD_DIR, record.stored_filename)
                if os.path.exists(old_path):
                    os.remove(old_path)
            record.original_filename = secure_filename(file.filename)
            record.stored_filename = secrets.token_hex(20) + ".pdf"
            file.save(os.path.join(UPLOAD_DIR, record.stored_filename))
        db.session.commit()
        create_qr(record)
        audit(record.id, "updated")
        flash("Record updated.", "success")
        return redirect(url_for("record_detail", record_id=record.id))
    return render_template("record_form.html", record=record, banks=active_banks, page_title="Edit Verification")


@app.route("/records/<int:record_id>")
@login_required
def record_detail(record_id):
    record = db.get_or_404(VerificationRecord, record_id)
    return render_template("record_detail.html", record=record)


@app.route("/records/<int:record_id>/revoke", methods=["POST"])
@login_required
def revoke_record(record_id):
    record = db.get_or_404(VerificationRecord, record_id)
    record.status = "revoked"
    db.session.commit()
    audit(record.id, "revoked")
    flash("Record revoked. Its public page will no longer show verified details.", "warning")
    return redirect(url_for("record_detail", record_id=record.id))


@app.route("/records/<int:record_id>/activate", methods=["POST"])
@login_required
def activate_record(record_id):
    record = db.get_or_404(VerificationRecord, record_id)
    record.status = "active"
    db.session.commit()
    audit(record.id, "activated")
    flash("Record activated.", "success")
    return redirect(url_for("record_detail", record_id=record.id))


@app.route("/qr/<code>")
@login_required
def qr_download(code):
    path = os.path.join(QR_DIR, code + ".png")
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=code + ".png")


@app.route("/qr-image/<code>")
@login_required
def qr_image(code):
    path = os.path.join(QR_DIR, code + ".png")
    if not os.path.exists(path):
        abort(404)
    return send_file(path, mimetype="image/png")


@app.route("/records/<int:record_id>/document")
@login_required
def private_document(record_id):
    record = db.get_or_404(VerificationRecord, record_id)
    if not record.stored_filename:
        abort(404)
    path = os.path.join(UPLOAD_DIR, record.stored_filename)
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=record.original_filename or "document.pdf")


@app.route("/verify/<code>")
def verify(code):
    record = VerificationRecord.query.filter_by(code=code).first()
    return render_template("verify.html", record=record, code=code)


@app.cli.command("create-admin")
def create_admin():
    username = input("Admin username: ").strip()
    password = input("Admin password: ").strip()
    if not username or not password:
        print("Username and password are required.")
        return
    if User.query.filter_by(username=username).first():
        print("That username already exists.")
        return
    db.session.add(User(username=username, password_hash=generate_password_hash(password, method="pbkdf2:sha256")))
    db.session.commit()
    print("Admin created successfully.")


def migrate_existing_sqlite():
    """Add the new bank_id column to an existing local SQLite database."""
    try:
        inspector = inspect(db.engine)
        columns = {c["name"] for c in inspector.get_columns("verification_record")}
        if "bank_id" not in columns:
            if db.engine.dialect.name == "sqlite":
                db.session.execute(text("ALTER TABLE verification_record ADD COLUMN bank_id INTEGER"))
                db.session.commit()
    except Exception:
        db.session.rollback()


with app.app_context():
    db.create_all()
    migrate_existing_sqlite()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
