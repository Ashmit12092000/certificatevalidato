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
from xhtml2pdf import pisa
from dateutil.relativedelta import relativedelta

# --- App Initialization ---
app = Flask(__name__)
app.secret_key = "supersecretkey"

DATABASE = 'databases.db'
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
            granted_software_modules TEXT,
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
            cert.*,
            customers.name as customer_name,
            latest_report.final_approver_notes as final_approver_notes_from_report -- Fetch the new column
        FROM certificates cert
        JOIN customers ON cert.customer_id = customers.id
        LEFT JOIN (
            SELECT
                customer_id,
                final_approver_notes,
                MAX(generated_date) as latest_generated_date
            FROM role_reports
            WHERE status = 'Completed'
            GROUP BY customer_id
        ) AS latest_report ON customers.id = latest_report.customer_id
        ORDER BY cert.id DESC
    """).fetchall()
    certificates_data_for_js = [dict(row) for row in certificates_raw]
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
    customers_raw = conn.execute("SELECT * FROM customers ORDER BY name ASC").fetchall()
    certificates_raw = conn.execute("SELECT * FROM certificates ORDER BY customer_id, cert_type ASC").fetchall()
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
            c.*,
            (SELECT COUNT(*) FROM certificates WHERE customer_id = c.id) as total_certs,
            latest_report.final_approver_notes AS final_approver_notes_from_report
        FROM customers c
        LEFT JOIN (
            SELECT
                customer_id,
                final_approver_notes,
                MAX(generated_date) as latest_generated_date
            FROM role_reports
            WHERE status = 'Completed'
            GROUP BY customer_id
        ) AS latest_report ON c.id = latest_report.customer_id
    """
    filters = []
    params = []

    if name_filter:
        filters.append("LOWER(c.name) LIKE ?")
        params.append(f"%{name_filter}%")
    # Keep these filters in the backend query even if not displayed in UI,
    # in case they are used for advanced search/reporting later.
    if email_filter:
        filters.append("LOWER(c.email) LIKE ?")
        params.append(f"%{email_filter}%")
    if gst_filter:
        filters.append("LOWER(c.gst) LIKE ?")
        params.append(f"%{gst_filter}%")

    if filters:
        query += " WHERE " + " AND ".join(filters)

    query += f" ORDER BY {sort_column} {order_by}"

    customers = conn.execute(query, params).fetchall()
    conn.close()

    return render_template("manage_customers.html",
                           customers=customers,
                           role=session.get("role"),
                           current_sort_by=sort_by,
                           current_order_by=order_by,
                           name_filter_val=name_filter,
                           email_filter_val=email_filter,
                           gst_filter_val=gst_filter,
                           request=request
                          )
@app.route('/customer-details/<int:customer_id>')
def customer_details(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    # Updated SQL query to include total_certs count for the specific customer
    customer = conn.execute("SELECT *, (SELECT COUNT(*) FROM certificates WHERE customer_id = customers.id) as total_certs FROM customers WHERE id = ?", (customer_id,)).fetchone()
    
    if not customer:
        flash("Customer not found.", "error")
        conn.close()
        return redirect(url_for('manage_customers'))

    certificates = conn.execute("""
        SELECT * FROM certificates WHERE customer_id = ? ORDER BY cert_type ASC
    """, (customer_id,)).fetchall()

    latest_report = conn.execute("""
        SELECT * FROM role_reports 
        WHERE customer_id = ? 
        ORDER BY generated_date DESC LIMIT 1
    """, (customer_id,)).fetchone()
    
    if latest_report:
        latest_report = dict(latest_report)
    else:
        latest_report = None

    all_software_apps = conn.execute("SELECT * FROM software_applications ORDER BY name").fetchall()
    all_software_modules = conn.execute("SELECT * FROM software_modules ORDER BY software_id, name").fetchall()
    
    software_apps_list = [dict(row) for row in all_software_apps]
    software_modules_list = [dict(row) for row in all_software_modules]
    
    all_software_apps_json = json.dumps(software_apps_list)
    all_software_modules_json = json.dumps(software_modules_list)


    conn.close()

    return render_template("customer_details.html", 
                           customer=customer, 
                           certificates=certificates,
                           latest_report=latest_report,
                           role=session.get("role"),
                           all_software_apps=software_apps_list,
                           all_software_modules_json=all_software_modules_json
                           )
@app.route('/customer-details/<int:customer_id>/pdf')
def generate_customer_pdf(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get("role") not in ["supervisor", "admin_hod"]:
        flash("Unauthorized to generate PDF report.", "error")
        return redirect(url_for('customer_details', customer_id=customer_id))

    conn = get_db_connection()
    customer = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    if not customer:
        flash("Customer not found.", "error")
        conn.close()
        return redirect(url_for('manage_customers'))

    certificates_raw = conn.execute("""
        SELECT * FROM certificates WHERE customer_id = ? ORDER BY cert_type ASC
    """, (customer_id,)).fetchall()
    certificates = [dict(row) for row in certificates_raw]

    # These lists are not strictly necessary for rendering granted_software_modules in PDF
    # because granted_software_modules already contains software_name and module_name.
    # However, they are passed for consistency with customer_details route context.
    all_software_apps = conn.execute("SELECT * FROM software_applications ORDER BY name").fetchall()
    all_software_modules = conn.execute("SELECT * FROM software_modules ORDER BY software_id, name").fetchall()
    
    software_apps_list = [dict(row) for row in all_software_apps]
    software_modules_list = [dict(row) for row in all_software_modules]

    conn.close()

    # Render HTML to a string using a dedicated PDF template
    rendered_html = render_template('pdf_customer_details.html',
                                    customer=customer,
                                    certificates=certificates,
                                    # Pass necessary data for granted_software_modules parsing if needed by from_json filter
                                    # all_software_apps=software_apps_list, # Not strictly used in PDF template for granted_software_modules display
                                    # all_software_modules_json=json.dumps(software_modules_list), # Not strictly used in PDF template for granted_software_modules display
                                    user_email=session.get('user_email'),
                                    current_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                   )

    # Create PDF
    pdf = pisa.CreatePDF(
        rendered_html,
        dest=None # file handle or path to write to, None to return StringIO
    )

    if not pdf.err:
        # Return the PDF as a file download
        return Response(pdf.dest.getvalue(), mimetype='application/pdf',
                        headers={'Content-Disposition': f'attachment;filename={customer["name"].replace(" ", "_")}_details.pdf'})
    
    flash("Error generating PDF.", "error")
    return redirect(url_for('customer_details', customer_id=customer_id))
@app.route('/update-customer/<int:customer_id>', methods=["POST"])
def update_customer(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get("role") not in ["supervisor", "admin_hod"]:
        flash("Unauthorized to update customer details.", "error")
        return redirect(url_for('customer_details', customer_id=customer_id))

    conn = get_db_connection()
    try:
        customer = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not customer:
            flash("Customer not found.", "error")
            return redirect(url_for('manage_customers'))

        name = request.form.get("name").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        pan = request.form.get("pan", "").strip()
        gst = request.form.get("gst", "").strip()
        address = request.form.get("address", "").strip()
        code = request.form.get("code", "").strip().upper()

        if not code or not name:
            flash("Customer ID and name are required.", "error")
            return redirect(url_for('customer_details', customer_id=customer_id))

        conn.execute("""
            UPDATE customers SET 
                code = ?, 
                name = ?, 
                address = ?, 
                email = ?, 
                phone = ?, 
                pan = ?, 
                gst = ?
            WHERE id = ?
        """, (code, name, address, email, phone, pan, gst, customer_id))
        conn.commit()
        flash("Customer details updated successfully!", "success")

    except Exception as e:
        print(f"Error updating customer {customer_id}: {e}")
        flash(f"Error updating customer details: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('customer_details', customer_id=customer_id))


@app.route('/manage-certificates')
def manage_certificates():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') not in ['supervisor', 'admin_hod']:
        flash("Unauthorized to manage certificate types.", "error")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    manual_types = conn.execute("SELECT name, 'manual' as source FROM certificate_types").fetchall()
    auto_types = conn.execute("SELECT DISTINCT cert_type as name, 'auto' as source FROM certificates").fetchall()
    conn.close()

    combined = manual_types + [r for r in auto_types if r['name'] not in [m['name'] for m in manual_types]]
    return render_template("manage_certificates.html", cert_types=combined)

@app.route('/add-cert-type', methods=["POST"])
def add_certificate_type():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get("role") not in ["supervisor", "admin_hod"]:
        flash("Unauthorized to add certificate types.", "error")
        return redirect(url_for('manage_certificates'))

    name = request.form.get('cert_name', '').strip()
    if not name:
        flash("Certificate name required", "error")
        return redirect(url_for('manage_certificates'))

    try:
        conn = get_db_connection()
        conn.execute("INSERT INTO certificate_types (name) VALUES (?)", (name,))
        conn.commit()
        conn.close()
        flash("Certificate type added successfully!", "success")
    except sqlite3.IntegrityError:
        flash("Certificate type already exists.", "error")

    return redirect(url_for('manage_certificates'))

@app.route('/delete-certificate-type', methods=["POST"])
def delete_certificate_type():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get('role') not in ['supervisor', 'admin_hod']:
        flash("Unauthorized to delete certificate types.", "error")
        return redirect(url_for('manage_certificates'))

    name = request.form.get("name").strip()
    source = request.form.get("source")

    conn = get_db_connection()
    try:
        if source == 'manual':
            conn.execute("DELETE FROM certificate_types WHERE name = ?", (name,))
        elif source == 'auto':
            conn.execute("DELETE FROM certificates WHERE cert_type = ?", (name,))
        conn.commit()
        flash(f"Deleted certificate type: {name}", "success")
    except Exception as e:
        flash(f"Error deleting certificate type: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('manage_certificates'))

@app.route('/report')
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    name_filter = request.args.get('name', '').strip().lower()
    status_filter = request.args.get('status', '')
    type_filter = request.args.get('type', '')
    sort_by = request.args.get('sort_by', 'c.name')
    order_by = request.args.get('order_by', 'ASC')

    valid_sort_columns = {
        'customer_id': 'c.id',
        'customer_name': 'c.name',
        'cert_type': 'cert.cert_type',
        'expiration_date': 'cert.expiration_date'
    }
    # Fallback to c.name if invalid
    sort_column = valid_sort_columns.get(sort_by, 'c.name')
    if order_by.upper() not in ['ASC', 'DESC']:
        order_by = 'ASC'

    conn = get_db_connection()

    query = f'''
        SELECT c.id AS customer_id, c.name AS customer_name, c.code AS customer_code,
               cert.cert_type, cert.status,
               cert.activation_date, cert.expiration_date,
               cert.verified, 
               (SELECT COUNT(*) FROM certificates WHERE customer_id = c.id) as total_certs
        FROM certificates cert
        JOIN customers c ON cert.customer_id = c.id
    '''

    filters = []
    params = []

    if name_filter:
        filters.append("LOWER(c.name) LIKE ?")
        params.append(f"%{name_filter}%")
    if status_filter:
        filters.append("cert.status = ?")
        params.append(status_filter)
    if type_filter:
        filters.append("cert.cert_type = ?")
        params.append(type_filter)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    query += f" ORDER BY {sort_column} {order_by}"

    report = conn.execute(query, params).fetchall()
    cert_types = [row["cert_type"] for row in conn.execute("SELECT DISTINCT cert_type FROM certificates").fetchall()]
    conn.close()

    return render_template("report.html", 
        report=report, 
        cert_types=cert_types,
        current_sort_by=sort_by,
        current_order_by=order_by,
        request=request
    )

@app.route('/download-report')
def download_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    name_filter = request.args.get('name', '').strip().lower()
    status_filter = request.args.get('status', '')
    type_filter = request.args.get('type', '')

    conn = get_db_connection()

    query = '''
        SELECT c.name AS customer_name, cert.cert_type, cert.status,
               cert.activation_date, cert.expiration_date, cert.verified
        FROM certificates cert
        JOIN customers c ON cert.customer_id = c.id
    '''
    filters = []
    params = []

    if name_filter:
        filters.append("LOWER(c.name) LIKE ?")
        params.append(f"%{name_filter}%")
    if status_filter:
        filters.append("cert.status = ?")
        params.append(status_filter)
    if type_filter:
        filters.append("cert.cert_type = ?")
        params.append(type_filter)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    query += " ORDER BY c.name ASC, cert.cert_type ASC"

    report = conn.execute(query, params).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Customer Name", "Certificate Type", "Status", "Activation Date", "Expiration Date", "Verified"])

    for row in report:
        writer.writerow([
            row["customer_name"], row["cert_type"], row["status"],
            row["activation_date"], row["expiration_date"], "Yes" if row["verified"] else "No"
        ])

    output.seek(0)
    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=customer_report.csv"})

@app.route('/add-customer', methods=["POST"])
def add_customer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get("role") not in ["operator", "supervisor", "admin_hod"]: 
        flash("Unauthorized to add customers.", "error")
        return redirect(url_for('dashboard'))

    code = request.form.get("code", "").strip().upper()
    name = request.form.get("name").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    pan = request.form.get("pan", "").strip()
    gst = request.form.get("gst", "").strip()
    address = request.form.get("address", "").strip()

    if not code or not name:
        flash("Customer ID and name are required", "error")
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO customers (code, name, address, email, phone, pan, gst, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (code, name, address, email, phone, pan, gst, 'Pending'))
        conn.commit()
        flash("Customer added successfully! Status: Pending for Approval.", "success")
    except Exception as e:
        flash(f"Error adding customer: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

@app.route('/add-certificate', methods=["POST"])
def add_certificate():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get("role") not in ["supervisor", "admin_hod"]:
        flash("Unauthorized to add certificates. Only Supervisor or Admin (HOD) can add certificates.", "error")
        return redirect(url_for('dashboard'))

    customer_id = request.form.get("customer_id")
    cert_type = request.form.get("cert_type", "").strip()
    expiration_date = request.form.get("expiration_date")
    activation_date = request.form.get("activation_date")

    # This is the JSON string of module data from hidden input
    selected_modules_raw = request.form.get("selected_modules")
    granted_software_modules = []
    selected_module_ids = []

    # Parse the JSON safely
    if selected_modules_raw:
        try:
            selected_module_data = json.loads(selected_modules_raw)
            granted_software_modules = selected_module_data
            selected_module_ids = [str(mod['module_id']) for mod in selected_module_data]
        except json.JSONDecodeError:
            flash("Failed to decode selected software/module data.", "error")
            return redirect(url_for('dashboard'))

    conn = get_db_connection()
    try:
        # Validate required fields
        if not customer_id or not cert_type or not expiration_date or not activation_date:
            flash("All fields are required to add a certificate.", "error")
            return redirect(url_for('dashboard'))

        act_date = datetime.strptime(activation_date, "%Y-%m-%d")
        exp_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        today = datetime.today().date()

        if act_date > exp_date:
            flash("Activation date cannot be later than Expiration date.", "error")
            return redirect(url_for('dashboard'))

        status = "Expired" if exp_date.date() < today else "Active"

        # Check duplicate certificate
        duplicate = conn.execute("""
            SELECT 1 FROM certificates
            WHERE customer_id = ? AND cert_type = ?
        """, (customer_id, cert_type)).fetchone()

        if duplicate:
            flash("This certificate already exists for the customer.", "error")
            return redirect(url_for('dashboard'))

        # Optional: Validate module IDs from DB (not strictly necessary if frontend is trusted)
        if selected_module_ids:
            placeholders = ','.join(['?'] * len(selected_module_ids))
            modules_data = conn.execute(f"""
                SELECT sm.id, sm.name as module_name, sa.name as software_name
                FROM software_modules sm
                JOIN software_applications sa ON sm.software_id = sa.id
                WHERE sm.id IN ({placeholders})
            """, selected_module_ids).fetchall()

            if len(modules_data) != len(selected_module_ids):
                flash("Some selected modules are invalid or missing.", "error")
                return redirect(url_for('dashboard'))

        # Insert certificate with granted software/module data
        conn.execute("""
            INSERT INTO certificates (
                customer_id, cert_type, status,
                activation_date, expiration_date,
                verified, granted_software_modules
            )
            VALUES (?, ?, ?, ?, ?, 0, ?)
        """, (
            customer_id,
            cert_type,
            status,
            act_date.strftime("%Y-%m-%d"),
            exp_date.strftime("%Y-%m-%d"),
            json.dumps(granted_software_modules)
        ))

        conn.commit()
        flash("Certificate added successfully! It requires approval.", "success")

    except Exception as e:
        print(f"Error adding certificate: {e}")
        flash(f"Error adding certificate: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

@app.route('/update-certificate-dates/<int:cert_id>', methods=["POST"])
def update_certificate_dates(cert_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get("role") not in ["supervisor", "admin_hod"]:
        flash("Unauthorized to modify certificate dates.", "error")
        return redirect(url_for('dashboard'))

    activation_date = request.form.get("activation_date")
    expiration_date = request.form.get("expiration_date")

    if not activation_date or not expiration_date:
        flash("Both activation and expiration dates are required.", "error")
        cert_info = get_db_connection().execute("SELECT customer_id FROM certificates WHERE id = ?", (cert_id,)).fetchone()
        if cert_info:
            return redirect(url_for('customer_details', customer_id=cert_info['customer_id']))
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    try:
        cert = conn.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)).fetchone()
        if not cert:
            flash("Certificate not found.", "error")
            return redirect(url_for('dashboard'))

        act_date_obj = datetime.strptime(activation_date, "%Y-%m-%d")
        exp_date_obj = datetime.strptime(expiration_date, "%Y-%m-%d")

        if act_date_obj > exp_date_obj:
            flash("Activation date cannot be later than Expiration date.", "error")
            return redirect(url_for('customer_details', customer_id=cert['customer_id']))

        today = datetime.today().date()
        new_status = "Expired" if exp_date_obj.date() < today else "Active"

        conn.execute("""
            UPDATE certificates SET 
                activation_date = ?, 
                expiration_date = ?, 
                status = ?,
                verified = 0 -- Reset verified status to 0
            WHERE id = ?
        """, (activation_date, expiration_date, new_status, cert_id))
        
        # Also reset customer status to Pending if it was Verified or Rejected
        customer_id = cert['customer_id']
        customer = conn.execute("SELECT status FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if customer and customer['status'] in ['Verified', 'Rejected']:
            conn.execute("UPDATE customers SET status = 'Pending' WHERE id = ?", (customer_id,))
            # Delete any existing role reports for this customer to clear the old workflow instance
            conn.execute("DELETE FROM role_reports WHERE customer_id = ?", (customer_id,))

        conn.commit()
        flash("Certificate dates updated successfully! Workflow re-enabled for approval.", "success")

    except Exception as e:
        print(f"Error updating certificate dates for cert_id {cert_id}: {e}")
        flash(f"Error updating certificate dates: {e}", "error")
    finally:
        conn.close()
    
    return redirect(url_for('customer_details', customer_id=cert['customer_id']))


@app.route('/generate-role-report/<int:customer_id>', methods=["POST"])
def generate_role_report(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get("role") not in ["supervisor", "admin_hod"]:
        flash("Unauthorized to generate role reports.", "error")
        return redirect(url_for('manage_customers'))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        customer = cursor.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not customer:
            flash("Customer not found.", "error")
            return redirect(url_for('manage_customers'))
        
        if customer['status'] != 'Pending':
            flash(f"Cannot generate report. Customer status is '{customer['status']}'.", "error")
            return redirect(url_for('manage_customers'))

        existing_report = cursor.execute("""
            SELECT id FROM role_reports WHERE customer_id = ? AND status = 'Awaiting Approval'
        """, (customer_id,)).fetchone()

        if existing_report:
            flash("A report for this customer is already awaiting approval.", "error")
            return redirect(url_for('manage_customers'))

        unverified_certs = cursor.execute("""
            SELECT cert_type FROM certificates WHERE customer_id = ? AND verified = 0
        """, (customer_id,)).fetchall()

        if not unverified_certs:
            flash("No unverified certificates found for this customer to generate a report.", "error")
            return redirect(url_for('manage_customers'))

        generated_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_status = "Awaiting Approval"

        cursor.execute("""
            INSERT INTO role_reports (customer_id, generated_date, status)
            VALUES (?, ?, ?)
        """, (customer_id, generated_date, report_status))
        report_id = cursor.lastrowid

        cursor.execute("UPDATE customers SET status = ? WHERE id = ?", ('Awaiting Approval', customer_id))
        
        conn.commit()

        flash(f"Role Report for {customer['name']} generated and sent for approval!", "success")
    except Exception as e:
        print(f"Error generating role report for customer_id {customer_id}: {e}")
        flash(f"Error generating role report: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('manage_customers'))

@app.route('/approval-queue')
def approval_queue():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get("role") != "admin_hod": # Changed to admin_hod only
        flash("Unauthorized access to approval queue.", "error")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    reports = conn.execute("""
        SELECT rr.*, c.name as customer_name, c.code as customer_code
        FROM role_reports rr
        JOIN customers c ON rr.customer_id = c.id
        WHERE rr.status IN ('Awaiting Approval', 'Final Approval Pending')
        ORDER BY rr.generated_date DESC
    """).fetchall()

    reports_with_certs = []
    for report in reports:
        report_dict = dict(report)
        if report['status'] == 'Awaiting Approval':
            certs = conn.execute("""
                SELECT cert_type, status, activation_date, expiration_date, granted_software_modules
                FROM certificates
                WHERE customer_id = ? AND verified = 0
            """, (report['customer_id'],)).fetchall()
            report_dict['certificates_for_approval'] = [dict(c) for c in certs]
        else:
            report_dict['certificates_for_approval'] = []
        
        reports_with_certs.append(report_dict)

    conn.close()
    return render_template('approval_queue.html', reports=reports_with_certs, role=session.get("role"))

@app.route('/approve-reject-report/<int:report_id>', methods=["POST"])
def approve_reject_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get("role") != "admin_hod": # Changed to admin_hod only
        flash("Unauthorized to approve/reject reports.", "error")
        return redirect(url_for('approval_queue'))

    conn = get_db_connection()
    try:
        report = conn.execute("""
            SELECT rr.*, c.name as customer_name, c.code as customer_code, c.status as customer_current_status
            FROM role_reports rr
            JOIN customers c ON rr.customer_id = c.id
            WHERE rr.id = ?
        """, (report_id,)).fetchone()

        if not report:
            flash("Role report not found.", "error")
            return redirect(url_for('approval_queue'))

        customer_id = report['customer_id']
        customer_name = report['customer_name'] 
        approver_notes = request.form.get('approver_notes', '').strip()
        
        if report['status'] != 'Awaiting Approval':
            flash("This report is not in the 'Awaiting Approval' state for certificate review.", "error")
            return redirect(url_for('approval_queue'))

        approved_cert_types = request.form.getlist('approve_cert_type') 
        rejected_cert_types = request.form.getlist('reject_cert_type') 

        all_certs_for_customer = conn.execute("""
            SELECT id, cert_type FROM certificates WHERE customer_id = ? AND verified = 0
        """, (customer_id,)).fetchall()

        approved_count = 0
        rejected_count = 0

        for cert in all_certs_for_customer:
            if cert['cert_type'] in approved_cert_types:
                approved_count += 1
            elif cert['cert_type'] in rejected_cert_types:
                conn.execute("UPDATE certificates SET status = 'Rejected' WHERE id = ?", (cert['id'],)) 
                rejected_count += 1

        if approved_count > 0:
            conn.execute("UPDATE customers SET status = ? WHERE id = ?", ('SSO Setup Pending', customer_id))
            conn.execute("UPDATE role_reports SET status = ?, approved_roles = ?, rejected_roles = ?, approver_notes = ? WHERE id = ?", 
                         ('SSO Setup Pending', json.dumps(approved_cert_types), json.dumps(rejected_cert_types), approver_notes, report_id))
            flash(f"Role Report for {customer_name} initially approved! Status changed to 'SSO Setup Pending'.", "success")
        else:
            conn.execute("UPDATE customers SET status = ? WHERE id = ?", ('Rejected', customer_id)) 
            conn.execute("UPDATE role_reports SET status = ?, approved_roles = ?, rejected_roles = ?, approver_notes = ? WHERE id = ?", 
                         ('Rejected', json.dumps(approved_cert_types), json.dumps(rejected_cert_types), approver_notes, report_id))
            flash(f"Role Report for {customer_name} rejected. No certificates verified.", "error")
        
        conn.commit()

    except Exception as e:
        print(f"Error processing initial report approval for report_id {report_id}: {e}")
        flash(f"Error processing initial report approval: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('approval_queue'))

@app.route('/mark-sso-complete/<int:customer_id>', methods=["POST"])
def mark_sso_complete(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get("role") not in ["supervisor", "admin_hod"]:
        flash("Unauthorized to mark SSO setup complete.", "error")
        return redirect(url_for('manage_customers'))

    conn = get_db_connection()
    try:
        customer = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not customer:
            flash("Customer not found.", "error")
            return redirect(url_for('manage_customers'))

        if customer['status'] != 'SSO Setup Pending':
            flash(f"Cannot mark SSO setup complete. Customer status is '{customer['status']}'.", "error")
            return redirect(url_for('manage_customers'))

        report = conn.execute("""
            SELECT id FROM role_reports 
            WHERE customer_id = ? AND status = 'SSO Setup Pending'
            ORDER BY generated_date DESC LIMIT 1
        """, (customer_id,)).fetchone()

        if not report:
            flash("No 'SSO Setup Pending' report found for this customer.", "error")
            return redirect(url_for('manage_customers'))

        report_id = report['id']

        conn.execute("UPDATE customers SET status = ? WHERE id = ?", ('Final Approval Pending', customer_id))
        conn.execute("UPDATE role_reports SET status = ? WHERE id = ?", ('Final Approval Pending', report_id))
        
        conn.commit()
        flash(f"SSO Setup for {customer['name']} marked complete. Sent for final approval!", "success")

    except Exception as e:
        print(f"Error marking SSO setup complete for customer_id {customer_id}: {e}")
        flash(f"Error marking SSO setup complete: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('manage_customers'))

@app.route('/final-confirm-sso/<int:report_id>', methods=["POST"])
def final_confirm_sso(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get("role") != "admin_hod": # Changed to admin_hod only
        flash("Unauthorized for final SSO confirmation.", "error")
        return redirect(url_for('approval_queue'))
    final_approver_notes = request.form.get('final_approver_notes', '').strip()

    conn = get_db_connection()
    try:
        report = conn.execute("""
            SELECT rr.*, c.name as customer_name, c.id as customer_id, c.status as customer_current_status
            FROM role_reports rr
            JOIN customers c ON rr.customer_id = c.id
            WHERE rr.id = ?
        """, (report_id,)).fetchone()

        if not report:
            flash("Role report not found for final confirmation.", "error")
            return redirect(url_for('approval_queue'))

        if report['status'] != 'Final Approval Pending' or report['customer_current_status'] != 'Final Approval Pending':
            flash("This report is not in the 'Final Approval Pending' state.", "error")
            return redirect(url_for('approval_queue'))

        customer_id = report['customer_id']
        customer_name = report['customer_name']

        approved_roles_json = report['approved_roles']
        approved_roles = json.loads(approved_roles_json) if approved_roles_json else []

        for cert_type in approved_roles:
            conn.execute("""
                UPDATE certificates SET verified = 1 
                WHERE customer_id = ? AND cert_type = ? AND verified = 0
            """, (customer_id, cert_type))

        conn.execute("UPDATE customers SET status = ? WHERE id = ?", ('Verified', customer_id))
        conn.execute("UPDATE role_reports SET status = ?, final_approver_notes = ? WHERE id = ?", ('Completed', final_approver_notes, report_id))
    
        conn.commit()
        flash(f"Final SSO confirmation for {customer_name} completed. Customer is now Verified!", "success")

    except Exception as e:
        print(f"Error during final SSO confirmation for report_id {report_id}: {e}")
        flash(f"Error during final SSO confirmation: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('approval_queue'))


@app.route('/verify/<int:cert_id>', methods=["POST"])
def verify(cert_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get("role") not in ["supervisor", "admin_hod"]:
        flash("Unauthorized to verify certificates.", "error")
        return redirect(url_for('dashboard'))

    try:
        conn = get_db_connection()
        cert = conn.execute("SELECT expiration_date FROM certificates WHERE id = ?", (cert_id,)).fetchone()
        if not cert:
            flash("Certificate not found", "error")
            return redirect(url_for('dashboard'))

        exp_date = datetime.strptime(cert["expiration_date"], "%Y-%m-%d")
        status = "Expired" if exp_date.date() < datetime.today().date() else "Active"

        conn.execute("""
            UPDATE certificates SET verified = 1, status = ? WHERE id = ?
        """, (status, cert_id))
        conn.commit()
        conn.close()

        flash("Certificate verified successfully!", "success")
    except Exception as e:
        flash(f"Verification failed: {e}", "error")

    return redirect(url_for('dashboard'))

@app.route('/delete-customer/<int:id>', methods=['POST'])
def delete_customer(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get("role") not in ["supervisor", "admin_hod"]:
        flash("Unauthorized access", "error")
        return redirect(url_for('manage_customers'))

    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM certificates WHERE customer_id = ?", (id,))
        conn.execute("DELETE FROM role_reports WHERE customer_id = ?", (id,))
        conn.execute("DELETE FROM customers WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        flash("Customer and all associated certificates and reports deleted.", "success")
    except Exception as e:
        flash(f"Error deleting customer: {e}", "error")

    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/manage-software')
def manage_software():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') not in ['supervisor', 'admin_hod']:
        flash("Unauthorized access to software management.", "error")
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    software_applications = conn.execute("SELECT * FROM software_applications ORDER BY name").fetchall()
    software_modules = conn.execute("""
        SELECT sm.id, sm.name as module_name, sa.name as software_name, sa.id as software_id
        FROM software_modules sm
        JOIN software_applications sa ON sm.software_id = sa.id
        ORDER BY sa.name, sm.name
    """).fetchall()
    conn.close()
    
    return render_template("manage_software.html", 
                           software_applications=software_applications, 
                           software_modules=software_modules,
                           role=session.get("role"))

@app.route('/add-software', methods=['POST'])
def add_software():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') not in ['supervisor', 'admin_hod']:
        flash("Unauthorized to add software.", "error")
        return redirect(url_for('manage_software'))
    
    software_name = request.form.get('software_name', '').strip()
    if not software_name:
        flash("Software name is required.", "error")
        return redirect(url_for('manage_software'))
    
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO software_applications (name) VALUES (?)", (software_name,))
        conn.commit()
        flash(f"Software '{software_name}' added successfully!", "success")
    except sqlite3.IntegrityError:
        flash(f"Software '{software_name}' already exists.", "error")
    except Exception as e:
        flash(f"Error adding software: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('manage_software'))

@app.route('/add-module', methods=['POST'])
def add_module():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') not in ['supervisor', 'admin_hod']:
        flash("Unauthorized to add module.", "error")
        return redirect(url_for('manage_software'))
    
    software_id = request.form.get('software_id')
    module_name = request.form.get('module_name', '').strip()
    
    if not software_id or not module_name:
        flash("Software and module name are required.", "error")
        return redirect(url_for('manage_software'))
    
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO software_modules (software_id, name) VALUES (?, ?)", (software_id, module_name))
        conn.commit()
        flash(f"Module '{module_name}' added successfully!", "success")
    except sqlite3.IntegrityError:
        flash(f"Module '{module_name}' already exists for this software.", "error")
    except Exception as e:
        flash(f"Error adding module: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('manage_software'))

@app.route('/delete-software/<int:software_id>', methods=['POST'])
def delete_software(software_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') not in ['supervisor', 'admin_hod']:
        flash("Unauthorized to delete software.", "error")
        return redirect(url_for('manage_software'))
    
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM software_modules WHERE software_id = ?", (software_id,))
        conn.execute("DELETE FROM software_applications WHERE id = ?", (software_id,))
        conn.commit()
        flash("Software and its modules deleted successfully!", "success")
    except Exception as e:
        flash(f"Error deleting software: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('manage_software'))

@app.route('/delete-module/<int:module_id>', methods=['POST'])
def delete_module(module_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') not in ['supervisor', 'admin_hod']:
        flash("Unauthorized to delete module.", "error")
        return redirect(url_for('manage_software'))
    
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM software_modules WHERE id = ?", (module_id,))
        conn.commit()
        flash("Module deleted successfully!", "success")
    except Exception as e:
        flash(f"Error deleting module: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('manage_software'))

@app.route('/get-modules-by-software/<int:software_id>')
def get_modules_by_software(software_id):
    conn = get_db_connection()
    modules = conn.execute("SELECT id, name FROM software_modules WHERE software_id = ? ORDER BY name", (software_id,)).fetchall()
    conn.close()
    modules_list = [dict(row) for row in modules]
    return jsonify(modules_list)


# --- Start Server ---
if __name__ == '__main__':
    init_db()
    app.run(debug=True, host="0.0.0.0", port=2000)
