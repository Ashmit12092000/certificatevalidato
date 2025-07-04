import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response,send_file
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re
import io
import csv
import random
import string
import json
from dateutil.relativedelta import relativedelta

# --- App Initialization ---
app = Flask(__name__)
app.secret_key = "supersecretkey"

DATABASE = 'databa.db' # Ensure this is your desired database file name
SUPERVISOR_EMAIL = "supervisor@gmail.com"
ADMIN_HOD_EMAIL = "admin@gmail.com"

# --- Custom Jinja2 Filters ---
def from_json_filter(value):
    """Custom Jinja2 filter to parse a JSON string."""
    if value is None:
        return []
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return []

app.jinja_env.filters['from_json'] = from_json_filter
app.jinja_env.globals['now'] = datetime.utcnow


# --- Database Setup ---
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()

        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT -- 'operator', 'supervisor', 'admin_hod'
        )''')

        cur.execute('''CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            name TEXT,
            address TEXT,
            phone TEXT,
            email TEXT,
            pan TEXT,
            gst TEXT,
            status TEXT DEFAULT 'Pending'
        )''')

        cur.execute('''CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            cert_type TEXT,
            status TEXT,
            activation_date TEXT,
            expiration_date TEXT,
            verified INTEGER DEFAULT 0,
            granted_software_modules TEXT DEFAULT '[]', -- Ensure DEFAULT '[]' is present
            final_notes TEXT DEFAULT '', -- IMPORTANT: This column must be present
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        )''')

        cur.execute('''CREATE TABLE IF NOT EXISTS certificate_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )''')

        cur.execute('''CREATE TABLE IF NOT EXISTS software_applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )''')

        cur.execute('''CREATE TABLE IF NOT EXISTS software_modules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            software_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            UNIQUE(software_id, name),
            FOREIGN KEY(software_id) REFERENCES software_applications(id) ON DELETE CASCADE
        )''')

        cur.execute('''CREATE TABLE IF NOT EXISTS role_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            generated_date TEXT NOT NULL,
            status TEXT NOT NULL,
            approved_roles TEXT,
            rejected_roles TEXT,
            approver_notes TEXT,
            final_approver_notes TEXT, 
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        )''')
        conn.commit()

# --- Helper Functions ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('login'))
# Add this GET route to your main.py
@app.route('/edit-customer-certificates/<int:customer_id>', methods=["GET"])
def edit_customer_certificates(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Only Supervisor and Admin (HOD) can access this page
    if session.get("role") not in ["supervisor", "admin_hod"]:
        flash("Unauthorized to edit customer certificates.", "error")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    customer = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    
    if not customer:
        flash("Customer not found.", "error")
        conn.close()
        return redirect(url_for('manage_customers'))

    # Fetch all certificates for this customer, including those that are rejected
    certificates_raw = conn.execute("""
        SELECT * FROM certificates WHERE customer_id = ? ORDER BY cert_type ASC
    """, (customer_id,)).fetchall()
    # Convert Row objects to dicts for JSON serialization in template
    certificates = [dict(row) for row in certificates_raw]


    # Fetch all master data needed for dropdowns in the form
    cert_types_query = conn.execute("SELECT name FROM certificate_types ORDER BY name ASC").fetchall()
    cert_types = [ct[0] for ct in cert_types_query]

    all_software_apps = conn.execute("SELECT * FROM software_applications ORDER BY name").fetchall()
    all_software_modules = conn.execute("SELECT * FROM software_modules ORDER BY software_id, name").fetchall()
    
    software_apps_list = [dict(row) for row in all_software_apps]
    software_modules_list = [dict(row) for row in all_software_modules]
    
    all_software_apps_json = json.dumps(software_apps_list)
    all_software_modules_json = json.dumps(software_modules_list)

    conn.close()

    return render_template("edit_customer_certificates.html", 
                           customer=customer, 
                           certificates=certificates, # Pass as list of dicts
                           cert_types=cert_types,
                           all_software_apps=software_apps_list, # Pass as list of dicts
                           all_software_modules_json=all_software_modules_json, # Pass as JSON string
                           role=session.get("role")
                           )

@app.route('/update-customer-certificates/<int:customer_id>', methods=["POST"])
def update_customer_certificates(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Only Supervisor and Admin (HOD) can update customer certificates
    if session.get("role") not in ["supervisor", "admin_hod"]:
        flash("Unauthorized to update customer certificates.", "error")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    try:
        customer = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not customer:
            flash("Customer not found.", "error")
            return redirect(url_for('manage_customers'))

        # Parse the JSON string containing all certificate data from the form
        certificates_data_json = request.form.get('certificates_data')
        print("certificates_data_json: "+str(certificates_data_json))
        if not certificates_data_json:
            flash("No certificate data received for update.", "error")
            return redirect(url_for('edit_customer_certificates', customer_id=customer_id))
        
        updated_certificates = json.loads(certificates_data_json)

        for cert_data in updated_certificates:
            cert_id = cert_data['id']
            cert_type = cert_data['cert_type']
            activation_date = cert_data['activation_date']
            expiration_date = cert_data['expiration_date']
            granted_software_modules = cert_data['granted_software_modules'] # Already JSON stringified from JS

            # Calculate new status based on dates
            act_date_obj = datetime.strptime(activation_date, "%Y-%m-%d")
            exp_date_obj = datetime.strptime(expiration_date, "%Y-%m-%d")
            today = datetime.today().date()
            new_status = "Expired" if exp_date_obj.date() < today else "Active"

            conn.execute("""
                UPDATE certificates SET 
                    cert_type = ?,
                    activation_date = ?, 
                    expiration_date = ?, 
                    status = ?,
                    verified = 0, -- Reset verified status to 0
                    granted_software_modules = ?
                WHERE id = ?
            """, (cert_type, activation_date, expiration_date, new_status, granted_software_modules, cert_id))
        
        # Reset customer status to Pending and delete old role reports
        conn.execute("UPDATE customers SET status = 'Pending' WHERE id = ?", (customer_id,))
        conn.execute("DELETE FROM role_reports WHERE customer_id = ?", (customer_id,))

        conn.commit()
        flash(f"Certificates for {customer['name']} updated successfully! Workflow re-enabled for approval.", "success")

    except Exception as e:
        print(f"Error updating customer certificates for customer_id {customer_id}: {e}")
        flash(f"Error updating customer certificates: {e}", "error")
    finally:
        conn.close()
    
    return redirect(url_for('manage_customers')) # Redirect to manage customers after re-submission

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session["user_id"] = user["id"]
            session["user_email"] = user["email"]
            if user["email"] == SUPERVISOR_EMAIL.lower():
                session["role"] = "supervisor"
            elif user["email"] == ADMIN_HOD_EMAIL.lower():
                session["role"] = "admin_hod"
            else:
                session["role"] = "operator"
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials", "error")
    return render_template('login.html')

@app.route('/signup', methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        hashed_pw = generate_password_hash(password)
        
        if email == SUPERVISOR_EMAIL.lower():
            role = "supervisor"
        elif email == ADMIN_HOD_EMAIL.lower():
            role = "admin_hod"
        else:
            role = "operator"

        try:
            conn = get_db_connection()
            conn.execute("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
                         (name, email, hashed_pw, role))
            conn.commit()
            conn.close()
            flash("Signup successful. Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Email already exists.", "error")
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()

    certificates_raw = conn.execute("""
        SELECT
            cert.id,
            cert.customer_id,
            cert.cert_type,
            cert.status,
            cert.activation_date,
            cert.expiration_date,
            cert.verified,
            COALESCE(cert.granted_software_modules, '[]') as granted_software_modules,
            COALESCE(cert.final_notes, '') as final_notes, -- Select final_notes directly from certificates table
            customers.name as customer_name
        FROM certificates cert
        JOIN customers ON cert.customer_id = customers.id
        ORDER BY cert.id DESC
    """).fetchall()
    certificates_data_for_js = [dict(row) for row in certificates_raw]


    all_customers = conn.execute("SELECT id, name, code, status FROM customers ORDER BY name").fetchall()
    cert_types_query = conn.execute("""
        SELECT name FROM certificate_types
        UNION
        SELECT DISTINCT cert_type FROM certificates
        ORDER BY name ASC
    """).fetchall()

    cert_types = [ct[0] for ct in cert_types_query]       

    all_software_apps = conn.execute("SELECT * FROM software_applications ORDER BY name").fetchall()
    all_software_modules = conn.execute("SELECT * FROM software_modules ORDER BY software_id, name").fetchall()
    
    software_apps_list = [dict(row) for row in all_software_apps]
    software_modules_list = [dict(row) for row in all_software_modules]
    
    all_software_apps_json = json.dumps(software_apps_list)
    all_software_modules_json = json.dumps(software_modules_list)
    
    certificates_json = json.dumps(certificates_data_for_js)

    conn.close()

    return render_template("dashboard.html",
                           certificates=certificates_raw,
                           certificates_json=certificates_json,
                           all_customers=all_customers,
                           cert_types=cert_types,
                           all_software_apps=software_apps_list,
                           all_software_modules_json=all_software_modules_json,
                           role=session.get("role"))
@app.route('/print-all-customers')
def print_all_customers():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get("role") not in ["supervisor", "admin_hod"]:
        flash("Unauthorized to print comprehensive customer report.", "error")
        return redirect(url_for('manage_customers'))

    conn = get_db_connection()
    customers_raw = conn.execute("""
        SELECT c.*,
        (SELECT COUNT(*) FROM certificates WHERE customer_id = c.id) as total_certs
        FROM customers c
    """).fetchall()
    
    certificates_raw = conn.execute("""
        SELECT *, COALESCE(final_notes, '') as final_notes FROM certificates ORDER BY customer_id, cert_type ASC
    """).fetchall()
    conn.close()

    customers_data = []
    customer_certs_map = {}
    for cert in certificates_raw:
        customer_certs_map.setdefault(cert['customer_id'], []).append(dict(cert))

    for cust in customers_raw:
        cust_dict = dict(cust)
        cust_dict['certificates'] = customer_certs_map.get(cust['id'], [])
        customers_data.append(cust_dict)

    user_email = session.get('user_email')
    user_role = session.get('role')

    return render_template("print_all_customers.html",
                           all_customers=customers_data,
                           user_email=user_email,
                           user_role=user_role)
@app.route('/import-csv', methods=['POST'])
def import_csv():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get("role") not in ["supervisor", "admin_hod"]:
        flash("Unauthorized to import CSV.", "error")
        return redirect(url_for('dashboard'))

    file = request.files.get('csv_file')
    if not file:
        flash("No file uploaded", "error")
        return redirect(url_for('dashboard'))

    try:
        content = file.read().decode('utf-8-sig')
        stream = io.StringIO(content)
        reader = csv.reader(stream)
        headers = next(reader)

        stream.seek(0)
        dict_reader = csv.DictReader(stream)

        customer_col = None
        for key in dict_reader.fieldnames:
            if key.strip().lower() == "customer name":
                customer_col = key
                break

        if not customer_col:
            flash("CSV must contain a 'Customer Name' column", "error")
            return redirect(url_for('dashboard'))

        conn = get_db_connection()
        cursor = conn.cursor()

        customer_count = 0
        certificate_count = 0
        seen_customers = set()

        for row in dict_reader:
            customer_name = (row.get(customer_col) or "").strip()
            if not customer_name:
                continue

            cursor.execute("SELECT id FROM customers WHERE name = ?", (customer_name,))
            customer = cursor.fetchone()
            if customer:
                customer_id = customer["id"]
            else:
                try:
                    cursor.execute(
                        "INSERT INTO customers (name, status) VALUES (?, ?)",
                        (customer_name, 'Pending') 
                    )
                    customer_id = cursor.lastrowid
                    customer_count += 1
                except sqlite3.IntegrityError as err:
                    cursor.execute("SELECT id FROM customers WHERE name = ?", (customer_name,))
                    existing = cursor.fetchone()
                    if existing:
                        customer_id = existing["id"]
                    else:
                        flash(f"Failed to insert or find customer: {customer_name}", "error")
                        continue

            seen_customers.add(customer_name)

            for col_key in row:
                if col_key.strip().lower() == "customer name":
                    continue

                value = (row.get(col_key) or "").strip()
                if not value or value == "-":
                    continue

                try:
                    date_str = value.split(" - ")[-1].strip().replace("/", "-")

                    try:
                        exp_date = datetime.strptime(date_str, "%m-%d-%Y")
                    except ValueError:
                        try:
                            exp_date = datetime.strptime(date_str, "%Y-%m-%d")
                        except ValueError:
                            continue

                    act_date = exp_date.replace(year=exp_date.year - 1)
                    status = "Expired" if exp_date.date() < datetime.today().date() else "Active"

                    cursor.execute("""
                        INSERT INTO certificates (customer_id, cert_type, status, activation_date, expiration_date, verified, granted_software_modules)
                        VALUES (?, ?, ?, ?, ?, 0, ?)
                    """, (
                        customer_id,
                        col_key.strip(),
                        status,
                        act_date.strftime("%Y-%m-%d"),
                        exp_date.strftime("%Y-%m-%d"),
                        json.dumps([])
                    ))
                    certificate_count += 1
                except Exception as cert_err:
                    print(f"Error inserting certificate for {customer_name} ({col_key}): {cert_err}")

                except Exception as parse_err:
                    print(f"Failed to parse certificate for {customer_name} - {col_key}: {parse_err}")
                    continue

        conn.commit()
        conn.close()

        flash(f"✅ Imported {customer_count} new customers and {certificate_count} certificates successfully!", "success")

    except Exception as e:
        flash(f"❌ Import failed: {e}", "error")

    return redirect(url_for('dashboard'))

@app.route('/manage-customers')
def manage_customers():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Filtering parameters
    name_filter = request.args.get('name_filter', '').strip().lower()
    email_filter = request.args.get('email_filter', '').strip().lower()
    gst_filter = request.args.get('gst_filter', '').strip().lower()

    # Sorting parameters
    sort_by = request.args.get('sort_by', 'name') # Default sort by name
    order_by = request.args.get('order_by', 'ASC') # Default order ASC

    valid_sort_columns = {
        'code': 'code',
        'name': 'name',
        'status': 'status'
    }

    sort_column = valid_sort_columns.get(sort_by, 'name')
    if order_by.upper() not in ['ASC', 'DESC']:
        order_by = 'ASC'

    conn = get_db_connection()

    # SQL query to fetch customers along with their total certificate count
    query = """
        SELECT
        