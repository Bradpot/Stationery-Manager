import os
import time
import jwt  # type: ignore
import bcrypt  # type: ignore
import sqlite3
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, g, send_from_directory
from database import get_db_connection, init_db, dict_from_row, list_from_rows

def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

JWT_SECRET = os.environ.get("SESSION_SECRET", "dev-insecure-secret")

app = Flask(__name__, static_folder="static", static_url_path="")

# Ensure database tables exist
init_db()

# CORS Helper
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    return response

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

# JWT Helpers
def sign_token(user_id, username):
    payload = {
        "userId": user_id,
        "username": username,
        "exp": utc_now() + timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None

# Authentication Decorator
def require_auth(f):
    def decorated(*args, **kwargs):
        if request.method == "OPTIONS":
            return "", 204
            
        header = request.headers.get("Authorization")
        token = None
        if header and header.startswith("Bearer "):
            token = header[len("Bearer "):]
            
        if not token:
            return jsonify({"error": "Authentication required"}), 401
            
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
            
        g.user = payload
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# Audit Log Helper
def record_activity(action, entity_type, entity_id=None, prev_qty=None, new_qty=None, details=None):
    user_id = g.user.get("userId") if "user" in g else None
    username = g.user.get("username") if "user" in g else None
    ip = request.remote_addr
    ua = request.headers.get("User-Agent")
    
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO activity_logs (
            user_id, username, action, entity_type, entity_id, 
            previous_quantity, new_quantity, details, ip_address, user_agent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, username, action, entity_type, entity_id, prev_qty, new_qty, details, ip, ua))
    conn.commit()
    conn.close()

# Inventory Status Helper
def compute_status(available_stock, minimum_stock):
    if available_stock <= 0:
        return "out_of_stock"
    if available_stock <= minimum_stock:
        return "low_stock"
    return "in_stock"

# Low Stock Notification Helper
def check_and_create_notification(item_id, item_name, available_stock, minimum_stock):
    status = compute_status(available_stock, minimum_stock)
    if status in ("low_stock", "out_of_stock"):
        msg = f"Low stock alert: {item_name} has only {available_stock} remaining (minimum threshold: {minimum_stock})."
        if available_stock <= 0:
            msg = f"Out of stock alert: {item_name} is completely out of stock."
            
        conn = get_db_connection()
        # Avoid duplicate unread notifications for the same item
        existing = conn.execute(
            "SELECT id FROM notifications WHERE type = ? AND message LIKE ? AND is_read = 0",
            ("low_stock", f"%{item_name}%")
        ).fetchone()
        
        if not existing:
            conn.execute(
                "INSERT INTO notifications (type, message, is_read) VALUES (?, ?, ?)",
                ("low_stock", msg, 0)
            )
            conn.commit()
        conn.close()

# Auth Routes
@app.route("/api/auth/setup-status", methods=["GET"])
def setup_status():
    conn = get_db_connection()
    row = conn.execute("SELECT id FROM users LIMIT 1").fetchone()
    conn.close()
    return jsonify({"adminExists": row is not None})

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.json
    full_name = data.get("fullName")
    office_name = data.get("officeName")
    email = data.get("email")
    phone = data.get("phone")
    username = data.get("username")
    password = data.get("password")
    confirm_password = data.get("confirmPassword")
    
    if not all([full_name, office_name, email, phone, username, password, confirm_password]):
        return jsonify({"error": "All fields are required"}), 400
        
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400
        
    conn = get_db_connection()
    existing = conn.execute("SELECT id FROM users LIMIT 1").fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "An administrator is already registered"}), 409
        
    # Check for duplicate email or username
    dup = conn.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email)).fetchone()
    if dup:
        conn.close()
        return jsonify({"error": "Username or email already exists"}), 400
        
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (full_name, office_name, email, phone, username, password_hash, role)
        VALUES (?, ?, ?, ?, ?, ?, 'admin')
    """, (full_name, office_name, email, phone, username, password_hash))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    token = sign_token(user_id, username)
    
    # Temporarily set credentials in g for audit log
    g.user = {"userId": user_id, "username": username}
    record_activity("register", "user", user_id, details="First administrator registered")
    
    return jsonify({
        "token": token,
        "user": {
            "id": user_id,
            "fullName": full_name,
            "officeName": office_name,
            "email": email,
            "phone": phone,
            "username": username,
            "role": "admin",
            "createdAt": utc_now().isoformat()
        }
    }), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json
    identifier = data.get("identifier")
    password = data.get("password")
    print(f"[LOGIN DEBUG] identifier: {identifier}, password: {password}")
    
    if not identifier or not password:
        return jsonify({"error": "Identifier and password are required"}), 400
        
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier)).fetchone()
    conn.close()
    
    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        return jsonify({"error": "Invalid credentials"}), 401
        
    token = sign_token(user["id"], user["username"])
    
    g.user = {"userId": user["id"], "username": user["username"]}
    record_activity("login", "user", user["id"])
    
    return jsonify({
        "token": token,
        "user": {
            "id": user["id"],
            "fullName": user["full_name"],
            "officeName": user["office_name"],
            "email": user["email"],
            "phone": user["phone"],
            "username": user["username"],
            "role": user["role"],
            "createdAt": user["created_at"]
        }
    })

@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def logout():
    record_activity("logout", "user", g.user["userId"])
    return jsonify({"message": "Logged out"})

@app.route("/api/auth/me", methods=["GET"])
@require_auth
def me():
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (g.user["userId"],)).fetchone()
    conn.close()
    
    if not user:
        return jsonify({"error": "User not found"}), 401
        
    return jsonify({
        "id": user["id"],
        "fullName": user["full_name"],
        "officeName": user["office_name"],
        "email": user["email"],
        "phone": user["phone"],
        "username": user["username"],
        "role": user["role"],
        "createdAt": user["created_at"]
    })

@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json
    identifier = data.get("identifier")
    
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier)).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "No account matches that email or username"}), 404
        
    import random
    code = str(random.randint(100000, 999999))
    expires_at = (utc_now() + timedelta(minutes=5)).isoformat()
    
    conn.execute(
        "INSERT INTO password_reset_otps (user_id, code, expires_at) VALUES (?, ?, ?)",
        (user["id"], code, expires_at)
    )
    conn.commit()
    conn.close()
    
    return jsonify({
        "message": "A one-time code has been generated. No email provider is connected, so it is returned below for demo purposes.",
        "expiresAt": expires_at,
        "demoOtp": code
    })

@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    data = request.json
    identifier = data.get("identifier")
    code = data.get("code")
    new_password = data.get("newPassword")
    
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier)).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "Invalid code"}), 400
        
    otp = conn.execute("""
        SELECT * FROM password_reset_otps 
        WHERE user_id = ? AND code = ? AND used = 'false'
        ORDER BY created_at DESC LIMIT 1
    """, (user["id"], code)).fetchone()
    
    if not otp:
        conn.close()
        return jsonify({"error": "Invalid or expired code"}), 400
        
    # Check expiry date
    exp = datetime.fromisoformat(otp["expires_at"])
    if exp < utc_now():
        conn.close()
        return jsonify({"error": "Invalid or expired code"}), 400
        
    password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user["id"]))
    conn.execute("UPDATE password_reset_otps SET used = 'true' WHERE id = ?", (otp["id"],))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Password has been reset"})

# Office Settings Routes
@app.route("/api/office-settings", methods=["GET"])
@require_auth
def get_office_settings():
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM office_settings LIMIT 1").fetchone()
    if not row:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO office_settings (office_name) VALUES ('My Office')")
        conn.commit()
        row = conn.execute("SELECT * FROM office_settings WHERE id = ?", (cursor.lastrowid,)).fetchone()
    conn.close()
    return jsonify(dict_from_row(row))

@app.route("/api/office-settings", methods=["PATCH"])
@require_auth
def update_office_settings():
    data = request.json
    conn = get_db_connection()
    row = conn.execute("SELECT id FROM office_settings LIMIT 1").fetchone()
    
    fields = []
    values = []
    for k, v in data.items():
        fields.append(f"{k} = ?")
        values.append(v)
        
    if not fields:
        conn.close()
        return jsonify({"error": "No fields to update"}), 400
        
    if not row:
        # Create settings if they do not exist
        cursor = conn.cursor()
        cursor.execute("INSERT INTO office_settings (office_name) VALUES ('My Office')")
        conn.commit()
        settings_id = cursor.lastrowid
    else:
        settings_id = row["id"]
        
    values.append(settings_id)
    conn.execute(f"UPDATE office_settings SET {', '.join(fields)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", values)
    conn.commit()
    
    updated = conn.execute("SELECT * FROM office_settings WHERE id = ?", (settings_id,)).fetchone()
    conn.close()
    
    record_activity("update", "office_settings", settings_id)
    return jsonify(dict_from_row(updated))

# Categories Routes
@app.route("/api/categories", methods=["GET"])
@require_auth
def get_categories():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT c.*, 
               (SELECT COUNT(*) FROM inventory_items WHERE category_id = c.id AND deleted_at IS NULL) as item_count
        FROM categories c
        WHERE c.deleted_at IS NULL
        ORDER BY c.name ASC
    """).fetchall()
    conn.close()
    
    results = []
    for r in rows:
        c = dict(r)
        c["itemCount"] = c.pop("item_count")
        c["createdAt"] = c.pop("created_at")
        c["updatedAt"] = c.pop("updated_at")
        results.append(c)
    return jsonify(results)

@app.route("/api/categories", methods=["POST"])
@require_auth
def create_category():
    data = request.json
    name = data.get("name")
    description = data.get("description")
    
    if not name:
        return jsonify({"error": "Category name is required"}), 400
        
    conn = get_db_connection()
    existing = conn.execute("SELECT id FROM categories WHERE name = ? AND deleted_at IS NULL", (name,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "Category already exists"}), 400
        
    cursor = conn.cursor()
    cursor.execute("INSERT INTO categories (name, description) VALUES (?, ?)", (name, description))
    cat_id = cursor.lastrowid
    conn.commit()
    
    created = conn.execute("SELECT * FROM categories WHERE id = ?", (cat_id,)).fetchone()
    conn.close()
    
    record_activity("create", "category", cat_id)
    c = dict(created)
    c["createdAt"] = c.pop("created_at")
    c["updatedAt"] = c.pop("updated_at")
    c["itemCount"] = 0
    return jsonify(c), 201

@app.route("/api/categories/<int:cat_id>", methods=["PATCH"])
@require_auth
def update_category(cat_id):
    data = request.json
    name = data.get("name")
    description = data.get("description")
    
    conn = get_db_connection()
    cat = conn.execute("SELECT * FROM categories WHERE id = ? AND deleted_at IS NULL", (cat_id,)).fetchone()
    if not cat:
        conn.close()
        return jsonify({"error": "Category not found"}), 404
        
    conn.execute("UPDATE categories SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (name, description, cat_id))
    conn.commit()
    
    updated = conn.execute("SELECT * FROM categories WHERE id = ?", (cat_id,)).fetchone()
    conn.close()
    
    record_activity("update", "category", cat_id)
    c = dict(updated)
    c["createdAt"] = c.pop("created_at")
    c["updatedAt"] = c.pop("updated_at")
    
    conn = get_db_connection()
    c["itemCount"] = conn.execute("SELECT COUNT(*) FROM inventory_items WHERE category_id = ? AND deleted_at IS NULL", (cat_id,)).fetchone()[0]
    conn.close()
    return jsonify(c)

@app.route("/api/categories/<int:cat_id>", methods=["DELETE"])
@require_auth
def delete_category(cat_id):
    conn = get_db_connection()
    cat = conn.execute("SELECT * FROM categories WHERE id = ? AND deleted_at IS NULL", (cat_id,)).fetchone()
    if not cat:
        conn.close()
        return jsonify({"error": "Category not found"}), 404
        
    conn.execute("UPDATE categories SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (cat_id,))
    conn.commit()
    conn.close()
    
    record_activity("delete", "category", cat_id)
    return "", 204

# Departments Routes
@app.route("/api/departments", methods=["GET"])
@require_auth
def get_departments():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM departments WHERE deleted_at IS NULL ORDER BY name ASC").fetchall()
    conn.close()
    return jsonify(list_from_rows(rows))

@app.route("/api/departments", methods=["POST"])
@require_auth
def create_department():
    data = request.json
    name = data.get("name")
    code = data.get("code")
    head_name = data.get("headName")
    phone = data.get("phone")
    email = data.get("email")
    description = data.get("description")
    
    if not name or not code:
        return jsonify({"error": "Name and code are required"}), 400
        
    conn = get_db_connection()
    existing = conn.execute("SELECT id FROM departments WHERE code = ? AND deleted_at IS NULL", (code,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "Department code must be unique"}), 400
        
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO departments (name, code, head_name, phone, email, description)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (name, code, head_name, phone, email, description))
    dept_id = cursor.lastrowid
    conn.commit()
    
    created = conn.execute("SELECT * FROM departments WHERE id = ?", (dept_id,)).fetchone()
    conn.close()
    
    record_activity("create", "department", dept_id)
    return jsonify(dict_from_row(created)), 201

@app.route("/api/departments/<int:dept_id>", methods=["PATCH"])
@require_auth
def update_department(dept_id):
    data = request.json
    name = data.get("name")
    code = data.get("code")
    head_name = data.get("headName")
    phone = data.get("phone")
    email = data.get("email")
    description = data.get("description")
    
    conn = get_db_connection()
    dept = conn.execute("SELECT * FROM departments WHERE id = ? AND deleted_at IS NULL", (dept_id,)).fetchone()
    if not dept:
        conn.close()
        return jsonify({"error": "Department not found"}), 404
        
    conn.execute("""
        UPDATE departments SET name = ?, code = ?, head_name = ?, phone = ?, email = ?, description = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (name, code, head_name, phone, email, description, dept_id))
    conn.commit()
    
    updated = conn.execute("SELECT * FROM departments WHERE id = ?", (dept_id,)).fetchone()
    conn.close()
    
    record_activity("update", "department", dept_id)
    return jsonify(dict_from_row(updated))

@app.route("/api/departments/<int:dept_id>", methods=["DELETE"])
@require_auth
def delete_department(dept_id):
    conn = get_db_connection()
    dept = conn.execute("SELECT * FROM departments WHERE id = ? AND deleted_at IS NULL", (dept_id,)).fetchone()
    if not dept:
        conn.close()
        return jsonify({"error": "Department not found"}), 404
        
    conn.execute("UPDATE departments SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (dept_id,))
    conn.commit()
    conn.close()
    
    record_activity("delete", "department", dept_id)
    return "", 204

# Suppliers Routes (Disabled)
@app.route("/api/suppliers", methods=["GET"])
@require_auth
def get_suppliers():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM suppliers WHERE deleted_at IS NULL ORDER BY name ASC").fetchall()
    conn.close()
    return jsonify(list_from_rows(rows))

@app.route("/api/suppliers", methods=["POST"])
@require_auth
def create_supplier():
    data = request.json
    name = data.get("name")
    contact_person = data.get("contactPerson")
    phone = data.get("phone")
    email = data.get("email")
    address = data.get("address")
    
    if not name:
        return jsonify({"error": "Supplier name is required"}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO suppliers (name, contact_person, phone, email, address)
        VALUES (?, ?, ?, ?, ?)
    """, (name, contact_person, phone, email, address))
    supplier_id = cursor.lastrowid
    conn.commit()
    
    created = conn.execute("SELECT * FROM suppliers WHERE id = ?", (supplier_id,)).fetchone()
    conn.close()
    
    record_activity("create", "supplier", supplier_id)
    return jsonify(dict_from_row(created)), 201

@app.route("/api/suppliers/<int:sup_id>", methods=["PATCH"])
@require_auth
def update_supplier(sup_id):
    data = request.json
    name = data.get("name")
    contact_person = data.get("contactPerson")
    phone = data.get("phone")
    email = data.get("email")
    address = data.get("address")
    
    conn = get_db_connection()
    sup = conn.execute("SELECT * FROM suppliers WHERE id = ? AND deleted_at IS NULL", (sup_id,)).fetchone()
    if not sup:
        conn.close()
        return jsonify({"error": "Supplier not found"}), 404
        
    conn.execute("""
        UPDATE suppliers SET name = ?, contact_person = ?, phone = ?, email = ?, address = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (name, contact_person, phone, email, address, sup_id))
    conn.commit()
    
    updated = conn.execute("SELECT * FROM suppliers WHERE id = ?", (sup_id,)).fetchone()
    conn.close()
    
    record_activity("update", "supplier", sup_id)
    return jsonify(dict_from_row(updated))

@app.route("/api/suppliers/<int:sup_id>", methods=["DELETE"])
@require_auth
def delete_supplier(sup_id):
    conn = get_db_connection()
    sup = conn.execute("SELECT * FROM suppliers WHERE id = ? AND deleted_at IS NULL", (sup_id,)).fetchone()
    if not sup:
        conn.close()
        return jsonify({"error": "Supplier not found"}), 404
        
    conn.execute("UPDATE suppliers SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (sup_id,))
    conn.commit()
    conn.close()
    
    record_activity("delete", "supplier", sup_id)
    return "", 204

# Item Code Generator helper in Python
def get_unique_item_code(category_name):
    prefix = "".join([c for c in category_name if c.isalpha()]).upper()[:3].ljust(3, 'X')
    
    conn = get_db_connection()
    count = conn.execute("SELECT COUNT(*) FROM inventory_items").fetchone()[0] + 1
    conn.close()
    
    # timestamp in base36:
    def base36encode(number):
        alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        base36 = ''
        while number:
            number, i = divmod(number, 36)
            base36 = alphabet[i] + base36
        return base36 or '0'
        
    suffix = base36encode(int(time.time()))[-5:] + str(count)
    return f"{prefix}-{suffix}"

# Inventory Routes
@app.route("/api/inventory", methods=["GET"])
@app.route("/api/inventory-items", methods=["GET"])
@require_auth
def get_inventory_items():
    search = request.args.get("search")
    category_id = request.args.get("categoryId")
    supplier_id = request.args.get("supplierId")
    status = request.args.get("status")
    
    query = """
        SELECT i.*, c.name as categoryName, s.name as supplierName, d.name as departmentName
        FROM inventory_items i
        LEFT JOIN categories c ON i.category_id = c.id
        LEFT JOIN suppliers s ON i.supplier_id = s.id
        LEFT JOIN departments d ON i.department_id = d.id
        WHERE i.deleted_at IS NULL
    """
    params = []
    
    if search:
        query += " AND i.name LIKE ?"
        params.append(f"%{search}%")
    if category_id:
        query += " AND i.category_id = ?"
        params.append(category_id)
    if supplier_id:
        query += " AND i.supplier_id = ?"
        params.append(supplier_id)
        
    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    results = []
    for r in rows:
        item = dict(r)
        item["purchasePrice"] = float(item["purchase_price"]) if item["purchase_price"] is not None else None
        # convert under_scored to camelCase for API compatibility
        item["categoryId"] = item.pop("category_id")
        item["itemCode"] = item.pop("item_code")
        item["supplierId"] = item.pop("supplier_id")
        item["purchaseDate"] = item.pop("purchase_date")
        item["purchasePrice"] = item.pop("purchase_price")
        # parse purchasePrice back to float or None
        item["purchasePrice"] = float(item["purchasePrice"]) if item["purchasePrice"] is not None else None
        item["totalPurchased"] = item.pop("total_purchased")
        item["totalIssued"] = item.pop("total_issued")
        item["totalReturned"] = item.pop("total_returned")
        item["availableStock"] = item.pop("available_stock")
        item["minimumStock"] = item.pop("minimum_stock")
        item["maximumStock"] = item.pop("maximum_stock")
        item["imageUrl"] = item.pop("image_url")
        item["createdAt"] = item.pop("created_at")
        item["updatedAt"] = item.pop("updated_at")
        item["deletedAt"] = item.pop("deleted_at")
        item["departmentId"] = item.pop("department_id")
        item["departmentName"] = item.pop("departmentName")
        
        # compute active status dynamic
        item["status"] = compute_status(item["availableStock"], item["minimumStock"])
        
        if not status or item["status"] == status:
            results.append(item)
            
    return jsonify(results)

@app.route("/api/inventory", methods=["POST"])
@app.route("/api/inventory-items", methods=["POST"])
@require_auth
def create_inventory_item():
    data = request.json
    name = data.get("name")
    category_id = data.get("categoryId")
    barcode = data.get("barcode")
    description = data.get("description")
    supplier_id = data.get("supplierId")
    purchase_date = data.get("purchaseDate")
    purchase_price = data.get("purchasePrice")
    unit = data.get("unit")
    initial_stock = data.get("initialStock", 0)
    minimum_stock = data.get("minimumStock", 0)
    maximum_stock = data.get("maximumStock")
    image_url = data.get("imageUrl")
    department_id = data.get("departmentId")
    
    if not name or not category_id or not unit:
        return jsonify({"error": "Name, category, and unit are required"}), 400
        
    conn = get_db_connection()
    cat = conn.execute("SELECT name FROM categories WHERE id = ?", (category_id,)).fetchone()
    if not cat:
        conn.close()
        return jsonify({"error": "Category not found"}), 400
        
    item_code = get_unique_item_code(cat["name"])
    status = compute_status(initial_stock, minimum_stock)
    
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO inventory_items (
            name, category_id, item_code, barcode, description, supplier_id,
            purchase_date, purchase_price, unit, total_purchased, available_stock,
            minimum_stock, maximum_stock, image_url, status, department_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        name, category_id, item_code, barcode, description, supplier_id,
        purchase_date, str(purchase_price) if purchase_price is not None else None, unit,
        initial_stock, initial_stock, minimum_stock, maximum_stock, image_url, status, department_id
    ))
    item_id = cursor.lastrowid
    conn.commit()
    
    created = conn.execute("""
        SELECT i.*, c.name as categoryName, s.name as supplierName, d.name as departmentName
        FROM inventory_items i
        LEFT JOIN categories c ON i.category_id = c.id
        LEFT JOIN suppliers s ON i.supplier_id = s.id
        LEFT JOIN departments d ON i.department_id = d.id
        WHERE i.id = ?
    """, (item_id,)).fetchone()
    conn.close()
    
    record_activity("create", "inventory_item", item_id)
    check_and_create_notification(item_id, name, initial_stock, minimum_stock)
    
    # Format to API response compatibility
    item = dict(created)
    item["categoryId"] = item.pop("category_id")
    item["itemCode"] = item.pop("item_code")
    item["supplierId"] = item.pop("supplier_id")
    item["purchaseDate"] = item.pop("purchase_date")
    item["purchasePrice"] = float(item.pop("purchase_price")) if item.get("purchase_price") else None
    item["totalPurchased"] = item.pop("total_purchased")
    item["totalIssued"] = item.pop("total_issued")
    item["totalReturned"] = item.pop("total_returned")
    item["availableStock"] = item.pop("available_stock")
    item["minimumStock"] = item.pop("minimum_stock")
    item["maximumStock"] = item.pop("maximum_stock")
    item["imageUrl"] = item.pop("image_url")
    item["createdAt"] = item.pop("created_at")
    item["updatedAt"] = item.pop("updated_at")
    item["deletedAt"] = item.pop("deleted_at")
    item["status"] = status
    item["departmentId"] = item.pop("department_id")
    item["departmentName"] = item.pop("departmentName")
    
    return jsonify(item), 201

@app.route("/api/inventory/<int:item_id>", methods=["GET"])
@app.route("/api/inventory-items/<int:item_id>", methods=["GET"])
@require_auth
def get_inventory_item(item_id):
    conn = get_db_connection()
    row = conn.execute("""
        SELECT i.*, c.name as categoryName, s.name as supplierName, d.name as departmentName
        FROM inventory_items i
        LEFT JOIN categories c ON i.category_id = c.id
        LEFT JOIN suppliers s ON i.supplier_id = s.id
        LEFT JOIN departments d ON i.department_id = d.id
        WHERE i.id = ? AND i.deleted_at IS NULL
    """, (item_id,)).fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Inventory item not found"}), 404
        
    item = dict(row)
    item["categoryId"] = item.pop("category_id")
    item["itemCode"] = item.pop("item_code")
    item["supplierId"] = item.pop("supplier_id")
    item["purchaseDate"] = item.pop("purchase_date")
    item["purchasePrice"] = float(item.pop("purchase_price")) if item.get("purchase_price") else None
    item["totalPurchased"] = item.pop("total_purchased")
    item["totalIssued"] = item.pop("total_issued")
    item["totalReturned"] = item.pop("total_returned")
    item["availableStock"] = item.pop("available_stock")
    item["minimumStock"] = item.pop("minimum_stock")
    item["maximumStock"] = item.pop("maximum_stock")
    item["imageUrl"] = item.pop("image_url")
    item["createdAt"] = item.pop("created_at")
    item["updatedAt"] = item.pop("updated_at")
    item["deletedAt"] = item.pop("deleted_at")
    item["status"] = compute_status(item["availableStock"], item["minimumStock"])
    item["departmentId"] = item.pop("department_id")
    item["departmentName"] = item.pop("departmentName")
    
    return jsonify(item)

@app.route("/api/inventory/<int:item_id>", methods=["PATCH"])
@app.route("/api/inventory-items/<int:item_id>", methods=["PATCH"])
@require_auth
def update_inventory_item(item_id):
    data = request.json
    conn = get_db_connection()
    existing = conn.execute("SELECT * FROM inventory_items WHERE id = ? AND deleted_at IS NULL", (item_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({"error": "Inventory item not found"}), 404
        
    fields = []
    values = []
    
    # Map camelCase to snake_case
    key_mapping = {
        "name": "name",
        "categoryId": "category_id",
        "barcode": "barcode",
        "description": "description",
        "supplierId": "supplier_id",
        "purchaseDate": "purchase_date",
        "purchasePrice": "purchase_price",
        "unit": "unit",
        "minimumStock": "minimum_stock",
        "maximumStock": "maximum_stock",
        "imageUrl": "image_url",
        "departmentId": "department_id"
    }
    
    for k, val in data.items():
        if k in key_mapping:
            fields.append(f"{key_mapping[k]} = ?")
            if k == "purchasePrice":
                values.append(str(val) if val is not None else None)
            else:
                values.append(val)
                
    min_stock = data.get("minimumStock", existing["minimum_stock"])
    new_status = compute_status(existing["available_stock"], min_stock)
    fields.append("status = ?")
    values.append(new_status)
    
    values.append(item_id)
    conn.execute(f"UPDATE inventory_items SET {', '.join(fields)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", values)
    conn.commit()
    
    updated_row = conn.execute("""
        SELECT i.*, c.name as categoryName, s.name as supplierName, d.name as departmentName
        FROM inventory_items i
        LEFT JOIN categories c ON i.category_id = c.id
        LEFT JOIN suppliers s ON i.supplier_id = s.id
        LEFT JOIN departments d ON i.department_id = d.id
        WHERE i.id = ?
    """, (item_id,)).fetchone()
    conn.close()
    
    record_activity("update", "inventory_item", item_id)
    check_and_create_notification(item_id, updated_row["name"], updated_row["available_stock"], min_stock)
    
    item = dict(updated_row)
    item["categoryId"] = item.pop("category_id")
    item["itemCode"] = item.pop("item_code")
    item["supplierId"] = item.pop("supplier_id")
    item["purchaseDate"] = item.pop("purchase_date")
    item["purchasePrice"] = float(item.pop("purchase_price")) if item.get("purchase_price") else None
    item["totalPurchased"] = item.pop("total_purchased")
    item["totalIssued"] = item.pop("total_issued")
    item["totalReturned"] = item.pop("total_returned")
    item["availableStock"] = item.pop("available_stock")
    item["minimumStock"] = item.pop("minimum_stock")
    item["maximumStock"] = item.pop("maximum_stock")
    item["imageUrl"] = item.pop("image_url")
    item["createdAt"] = item.pop("created_at")
    item["updatedAt"] = item.pop("updated_at")
    item["deletedAt"] = item.pop("deleted_at")
    item["status"] = new_status
    item["departmentId"] = item.pop("department_id")
    item["departmentName"] = item.pop("departmentName")
    
    return jsonify(item)

@app.route("/api/inventory/<int:item_id>", methods=["DELETE"])
@app.route("/api/inventory-items/<int:item_id>", methods=["DELETE"])
@require_auth
def delete_inventory_item(item_id):
    conn = get_db_connection()
    existing = conn.execute("SELECT id FROM inventory_items WHERE id = ? AND deleted_at IS NULL", (item_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({"error": "Inventory item not found"}), 404
        
    conn.execute("UPDATE inventory_items SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    
    record_activity("delete", "inventory_item", item_id)
    return "", 204

# Purchases Routes (Disabled)
@app.route("/api/purchases", methods=["GET"])
@require_auth
def get_purchases():
    item_id = request.args.get("itemId")
    supplier_id = request.args.get("supplierId")
    date_from = request.args.get("dateFrom")
    date_to = request.args.get("dateTo")
    
    query = """
        SELECT p.*, i.name as itemName, s.name as supplierName
        FROM purchases p
        INNER JOIN inventory_items i ON p.item_id = i.id
        INNER JOIN suppliers s ON p.supplier_id = s.id
        WHERE 1=1
    """
    params = []
    
    if item_id:
        query += " AND p.item_id = ?"
        params.append(item_id)
    if supplier_id:
        query += " AND p.supplier_id = ?"
        params.append(supplier_id)
    if date_from:
        query += " AND p.purchase_date >= ?"
        params.append(date_from)
    if date_to:
        query += " AND p.purchase_date <= ?"
        params.append(date_to)
        
    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    results = []
    for r in rows:
        p = dict(r)
        p["itemId"] = p.pop("item_id")
        p["supplierId"] = p.pop("supplier_id")
        p["invoiceNumber"] = p.pop("invoice_number")
        p["purchaseDate"] = p.pop("purchase_date")
        p["createdAt"] = p.pop("created_at")
        p["price"] = float(p["price"])
        results.append(p)
        
    return jsonify(results)

@app.route("/api/purchases", methods=["POST"])
@require_auth
def create_purchase():
    data = request.json
    item_id = data.get("itemId")
    supplier_id = data.get("supplierId")
    invoice_number = data.get("invoiceNumber")
    quantity = data.get("quantity")
    price = data.get("price")
    purchase_date = data.get("purchaseDate")
    
    if not all([item_id, supplier_id, invoice_number, quantity, price, purchase_date]):
        return jsonify({"error": "All fields are required"}), 400
        
    conn = get_db_connection()
    item = conn.execute("SELECT * FROM inventory_items WHERE id = ? AND deleted_at IS NULL", (item_id,)).fetchone()
    if not item:
        conn.close()
        return jsonify({"error": "Item not found"}), 400
        
    supplier = conn.execute("SELECT * FROM suppliers WHERE id = ? AND deleted_at IS NULL", (supplier_id,)).fetchone()
    if not supplier:
        conn.close()
        return jsonify({"error": "Supplier not found"}), 400
        
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO purchases (item_id, supplier_id, invoice_number, quantity, price, purchase_date)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (item_id, supplier_id, invoice_number, quantity, str(price), purchase_date))
    purchase_id = cursor.lastrowid
    
    total_purchased = item["total_purchased"] + quantity
    available_stock = item["available_stock"] + quantity
    new_status = compute_status(available_stock, item["minimum_stock"])
    
    conn.execute("""
        UPDATE inventory_items 
        SET total_purchased = ?, available_stock = ?, status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (total_purchased, available_stock, new_status, item_id))
    
    conn.commit()
    conn.close()
    
    record_activity(
        "purchase", "inventory_item", item_id,
        prev_qty=item["available_stock"], new_qty=available_stock,
        details=f"Purchased {quantity} {item['unit']} of {item['name']} from {supplier['name']}"
    )
    
    # Check if stock condition updated
    check_and_create_notification(item_id, item["name"], available_stock, item["minimum_stock"])
    
    return jsonify({
        "id": purchase_id,
        "itemId": item_id,
        "itemName": item["name"],
        "supplierId": supplier_id,
        "supplierName": supplier["name"],
        "invoiceNumber": invoice_number,
        "quantity": quantity,
        "price": float(price),
        "purchaseDate": purchase_date,
        "createdAt": utc_now().isoformat()
    }), 201
# 
@app.route("/api/purchases/<int:p_id>", methods=["GET"])
@require_auth
def get_purchase(p_id):
    conn = get_db_connection()
    row = conn.execute("""
        SELECT p.*, i.name as itemName, s.name as supplierName
        FROM purchases p
        INNER JOIN inventory_items i ON p.item_id = i.id
        INNER JOIN suppliers s ON p.supplier_id = s.id
        WHERE p.id = ?
    """, (p_id,)).fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Purchase not found"}), 404
        
    p = dict(row)
    p["itemId"] = p.pop("item_id")
    p["supplierId"] = p.pop("supplier_id")
    p["invoiceNumber"] = p.pop("invoice_number")
    p["purchaseDate"] = p.pop("purchase_date")
    p["createdAt"] = p.pop("created_at")
    p["price"] = float(p["price"])
    return jsonify(p)
# 
# # Issues Routes (Disabled)
@app.route("/api/issues", methods=["GET"])
@require_auth
def get_issues():
    department_id = request.args.get("departmentId")
    item_id = request.args.get("itemId")
    date_from = request.args.get("dateFrom")
    date_to = request.args.get("dateTo")
    
    query = """
        SELECT t.*, d.name as departmentName, i.name as itemName
        FROM issue_transactions t
        INNER JOIN departments d ON t.department_id = d.id
        INNER JOIN inventory_items i ON t.item_id = i.id
        WHERE 1=1
    """
    params = []
    
    if department_id:
        query += " AND t.department_id = ?"
        params.append(department_id)
    if item_id:
        query += " AND t.item_id = ?"
        params.append(item_id)
    if date_from:
        query += " AND t.issue_date >= ?"
        params.append(date_from)
    if date_to:
        query += " AND t.issue_date <= ?"
        params.append(date_to)
        
    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    results = []
    for r in rows:
        issue = dict(r)
        issue["departmentId"] = issue.pop("department_id")
        issue["receiverName"] = issue.pop("receiver_name")
        issue["employeeId"] = issue.pop("employee_id")
        issue["itemId"] = issue.pop("item_id")
        issue["quantityIssued"] = issue.pop("quantity_issued")
        issue["issueDate"] = issue.pop("issue_date")
        issue["createdAt"] = issue.pop("created_at")
        results.append(issue)
        
    return jsonify(results)

@app.route("/api/issues", methods=["POST"])
@require_auth
def create_issue():
    data = request.json
    department_id = data.get("departmentId")
    receiver_name = data.get("receiverName")
    employee_id = data.get("employeeId")
    item_id = data.get("itemId")
    quantity_issued = data.get("quantityIssued")
    purpose = data.get("purpose")
    remarks = data.get("remarks")
    issue_date = data.get("issueDate")
    
    if not all([department_id, receiver_name, item_id, quantity_issued, issue_date]):
        return jsonify({"error": "Required fields are missing"}), 400
        
    conn = get_db_connection()
    item = conn.execute("SELECT * FROM inventory_items WHERE id = ? AND deleted_at IS NULL", (item_id,)).fetchone()
    if not item:
        conn.close()
        return jsonify({"error": "Item not found"}), 400
        
    department = conn.execute("SELECT * FROM departments WHERE id = ? AND deleted_at IS NULL", (department_id,)).fetchone()
    if not department:
        conn.close()
        return jsonify({"error": "Department not found"}), 400
        
    if quantity_issued > item["available_stock"]:
        conn.close()
        return jsonify({"error": f"Only {item['available_stock']} {item['unit']} of {item['name']} are available"}), 400
        
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO issue_transactions (
            department_id, receiver_name, employee_id, item_id, quantity_issued, purpose, remarks, issue_date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (department_id, receiver_name, employee_id, item_id, quantity_issued, purpose, remarks, issue_date))
    issue_id = cursor.lastrowid
    
    total_issued = item["total_issued"] + quantity_issued
    available_stock = item["available_stock"] - quantity_issued
    new_status = compute_status(available_stock, item["minimum_stock"])
    
    conn.execute("""
        UPDATE inventory_items 
        SET total_issued = ?, available_stock = ?, status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (total_issued, available_stock, new_status, item_id))
    
    conn.commit()
    conn.close()
    
    record_activity(
        "issue", "inventory_item", item_id,
        prev_qty=item["available_stock"], new_qty=available_stock,
        details=f"Issued {quantity_issued} {item['unit']} of {item['name']} to {department['name']}"
    )
    
    # Check if stock condition updated
    check_and_create_notification(item_id, item["name"], available_stock, item["minimum_stock"])
    
    return jsonify({
        "id": issue_id,
        "departmentId": department_id,
        "departmentName": department["name"],
        "receiverName": receiver_name,
        "employeeId": employee_id,
        "itemId": item_id,
        "itemName": item["name"],
        "quantityIssued": quantity_issued,
        "purpose": purpose,
        "remarks": remarks,
        "issueDate": issue_date,
        "createdAt": utc_now().isoformat()
    }), 201

@app.route("/api/issues/<int:issue_id>", methods=["GET"])
@require_auth
def get_issue(issue_id):
    conn = get_db_connection()
    row = conn.execute("""
        SELECT t.*, d.name as departmentName, i.name as itemName
        FROM issue_transactions t
        INNER JOIN departments d ON t.department_id = d.id
        INNER JOIN inventory_items i ON t.item_id = i.id
        WHERE t.id = ?
    """, (issue_id,)).fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Issue not found"}), 404
        
    issue = dict(row)
    issue["departmentId"] = issue.pop("department_id")
    issue["receiverName"] = issue.pop("receiver_name")
    issue["employeeId"] = issue.pop("employee_id")
    issue["itemId"] = issue.pop("item_id")
    issue["quantityIssued"] = issue.pop("quantity_issued")
    issue["issueDate"] = issue.pop("issue_date")
    issue["createdAt"] = issue.pop("created_at")
    return jsonify(issue)
# 
# # Returns Routes (Disabled)
@app.route("/api/returns", methods=["GET"])
@require_auth
def get_returns():
    department_id = request.args.get("departmentId")
    item_id = request.args.get("itemId")
    date_from = request.args.get("dateFrom")
    date_to = request.args.get("dateTo")
    
    query = """
        SELECT r.*, d.name as departmentName, i.name as itemName
        FROM return_transactions r
        INNER JOIN departments d ON r.department_id = d.id
        INNER JOIN inventory_items i ON r.item_id = i.id
        WHERE 1=1
    """
    params = []
    
    if department_id:
        query += " AND r.department_id = ?"
        params.append(department_id)
    if item_id:
        query += " AND r.item_id = ?"
        params.append(item_id)
    if date_from:
        query += " AND r.return_date >= ?"
        params.append(date_from)
    if date_to:
        query += " AND r.return_date <= ?"
        params.append(date_to)
        
    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    results = []
    for row in rows:
        ret = dict(row)
        ret["departmentId"] = ret.pop("department_id")
        ret["itemId"] = ret.pop("item_id")
        ret["quantityReturned"] = ret.pop("quantity_returned")
        ret["returnDate"] = ret.pop("return_date")
        ret["createdAt"] = ret.pop("created_at")
        results.append(ret)
        
    return jsonify(results)

@app.route("/api/returns", methods=["POST"])
@require_auth
def create_return():
    data = request.json
    department_id = data.get("departmentId")
    item_id = data.get("itemId")
    quantity_returned = data.get("quantityReturned")
    reason = data.get("reason")
    remarks = data.get("remarks")
    return_date = data.get("returnDate")
    
    if not all([department_id, item_id, quantity_returned, return_date]):
        return jsonify({"error": "Required fields are missing"}), 400
        
    conn = get_db_connection()
    item = conn.execute("SELECT * FROM inventory_items WHERE id = ? AND deleted_at IS NULL", (item_id,)).fetchone()
    if not item:
        conn.close()
        return jsonify({"error": "Item not found"}), 400
        
    department = conn.execute("SELECT * FROM departments WHERE id = ? AND deleted_at IS NULL", (department_id,)).fetchone()
    if not department:
        conn.close()
        return jsonify({"error": "Department not found"}), 400
        
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO return_transactions (department_id, item_id, quantity_returned, reason, remarks, return_date)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (department_id, item_id, quantity_returned, reason, remarks, return_date))
    return_id = cursor.lastrowid
    
    total_returned = item["total_returned"] + quantity_returned
    available_stock = item["available_stock"] + quantity_returned
    new_status = compute_status(available_stock, item["minimum_stock"])
    
    conn.execute("""
        UPDATE inventory_items 
        SET total_returned = ?, available_stock = ?, status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (total_returned, available_stock, new_status, item_id))
    
    conn.commit()
    conn.close()
    
    record_activity(
        "return", "inventory_item", item_id,
        prev_qty=item["available_stock"], new_qty=available_stock,
        details=f"Returned {quantity_returned} {item['unit']} of {item['name']} from {department['name']}"
    )
    
    return jsonify({
        "id": return_id,
        "departmentId": department_id,
        "departmentName": department["name"],
        "itemId": item_id,
        "itemName": item["name"],
        "quantityReturned": quantity_returned,
        "reason": reason,
        "remarks": remarks,
        "returnDate": return_date,
        "createdAt": utc_now().isoformat()
    }), 201

@app.route("/api/returns/<int:r_id>", methods=["GET"])
@require_auth
def get_return(r_id):
    conn = get_db_connection()
    row = conn.execute("""
        SELECT r.*, d.name as departmentName, i.name as itemName
        FROM return_transactions r
        INNER JOIN departments d ON r.department_id = d.id
        INNER JOIN inventory_items i ON r.item_id = i.id
        WHERE r.id = ?
    """, (r_id,)).fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Return not found"}), 404
        
    ret = dict(row)
    ret["departmentId"] = ret.pop("department_id")
    ret["itemId"] = ret.pop("item_id")
    ret["quantityReturned"] = ret.pop("quantity_returned")
    ret["returnDate"] = ret.pop("return_date")
    ret["createdAt"] = ret.pop("created_at")
    return jsonify(ret)

# Dashboard Routes
def last_n_month_keys(n=6):
    keys = []
    now = utc_now()
    for i in range(n - 1, -1, -1):
        # Subtract i months
        year = now.year
        month = now.month - i
        while month <= 0:
            month += 12
            year -= 1
        keys.append(f"{year:04d}-{month:02d}")
    return keys

# Dashboard Routes (Disabled)
@app.route("/api/dashboard/summary", methods=["GET"])
@require_auth
def dashboard_summary():
    conn = get_db_connection()
    
    # 1. Total items count
    items = conn.execute("SELECT * FROM inventory_items WHERE deleted_at IS NULL").fetchall()
    
    # 2. Total categories
    categories_cnt = conn.execute("SELECT COUNT(*) FROM categories WHERE deleted_at IS NULL").fetchone()[0]
    
    # 3. Total departments
    depts_cnt = conn.execute("SELECT COUNT(*) FROM departments WHERE deleted_at IS NULL").fetchone()[0]
    
    total_stock = sum(item["available_stock"] for item in items)
    inventory_val = sum(item["available_stock"] * float(item["purchase_price"] or 0) for item in items)
    
    low_stock_cnt = sum(1 for item in items if compute_status(item["available_stock"], item["minimum_stock"]) == "low_stock")
    out_of_stock_cnt = sum(1 for item in items if compute_status(item["available_stock"], item["minimum_stock"]) == "out_of_stock")
    
    # Today's issued items quantity sum
    today_start = utc_now().strftime("%Y-%m-%d")
    today_issued = conn.execute("""
        SELECT COALESCE(SUM(quantity_issued), 0) 
        FROM issue_transactions 
        WHERE created_at LIKE ?
    """, (f"{today_start}%",)).fetchone()[0]
    
    # 6 Months distribution
    months = last_n_month_keys(6)
    purchases = conn.execute("SELECT quantity, purchase_date FROM purchases").fetchall()
    issues = conn.execute("SELECT quantity_issued, issue_date FROM issue_transactions").fetchall()
    returns = conn.execute("SELECT quantity_returned, return_date FROM return_transactions").fetchall()
    
    monthly_dist = []
    for month in months:
        monthly_dist.append({
            "month": month,
            "purchased": sum(p["quantity"] for p in purchases if p["purchase_date"].startswith(month)),
            "issued": sum(i["quantity_issued"] for i in issues if i["issue_date"].startswith(month)),
            "returned": sum(r["quantity_returned"] for r in returns if r["return_date"].startswith(month))
        })
        
    conn.close()
    
    return jsonify({
        "totalItems": len(items),
        "totalCategories": categories_cnt,
        "totalDepartments": depts_cnt,
        "totalStock": total_stock,
        "inventoryValue": inventory_val,
        "lowStockCount": low_stock_cnt,
        "outOfStockCount": out_of_stock_cnt,
        "todayIssuedItems": today_issued,
        "monthlyDistribution": monthly_dist
    })
# 
@app.route("/api/dashboard/recent-activities", methods=["GET"])
@require_auth
def recent_activities():
    limit = request.args.get("limit", 20, type=int)
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "action": r["action"],
            "entityType": r["entity_type"],
            "message": r["details"] or f"{r['action']} {r['entity_type']}",
            "createdAt": r["created_at"]
        })
    return jsonify(results)

@app.route("/api/dashboard/inventory-trends", methods=["GET"])
@require_auth
def inventory_trends():
    n_months = request.args.get("months", 6, type=int)
    months = last_n_month_keys(n_months)
    
    conn = get_db_connection()
    purchases = conn.execute("SELECT quantity, purchase_date FROM purchases").fetchall()
    issues = conn.execute("SELECT quantity_issued, issue_date FROM issue_transactions").fetchall()
    returns = conn.execute("SELECT quantity_returned, return_date FROM return_transactions").fetchall()
    conn.close()
    
    trends = []
    for month in months:
        trends.append({
            "month": month,
            "purchased": sum(p["quantity"] for p in purchases if p["purchase_date"].startswith(month)),
            "issued": sum(i["quantity_issued"] for i in issues if i["issue_date"].startswith(month)),
            "returned": sum(r["quantity_returned"] for r in returns if r["return_date"].startswith(month))
        })
    return jsonify(trends)

@app.route("/api/dashboard/department-stats", methods=["GET"])
@require_auth
def department_stats():
    conn = get_db_connection()
    depts = conn.execute("SELECT * FROM departments WHERE deleted_at IS NULL").fetchall()
    issues = conn.execute("SELECT quantity_issued, department_id FROM issue_transactions").fetchall()
    returns = conn.execute("SELECT quantity_returned, department_id FROM return_transactions").fetchall()
    conn.close()
    
    stats = []
    for d in depts:
        stats.append({
            "departmentId": d["id"],
            "departmentName": d["name"],
            "totalIssued": sum(i["quantity_issued"] for i in issues if i["department_id"] == d["id"]),
            "totalReturned": sum(r["quantity_returned"] for r in returns if r["department_id"] == d["id"])
        })
    return jsonify(stats)
# 
# # Analytics Route (Disabled)
@app.route("/api/analytics/overview", methods=["GET"])
@require_auth
def analytics_overview():
    conn = get_db_connection()
    items = conn.execute("SELECT * FROM inventory_items WHERE deleted_at IS NULL").fetchall()
    purchases = conn.execute("SELECT * FROM purchases").fetchall()
    issues = conn.execute("SELECT * FROM issue_transactions").fetchall()
    returns = conn.execute("SELECT * FROM return_transactions").fetchall()
    departments = conn.execute("SELECT * FROM departments WHERE deleted_at IS NULL").fetchall()
    conn.close()

    inventory_value = sum(item["available_stock"] * float(item["purchase_price"] or 0) for item in items)

    months = last_n_month_keys(6)
    
    # stock movement
    stock_movement = []
    for month in months:
        stock_movement.append({
            "month": month,
            "purchased": sum(p["quantity"] for p in purchases if p["purchase_date"].startswith(month)),
            "issued": sum(i["quantity_issued"] for i in issues if i["issue_date"].startswith(month)),
            "returned": sum(r["quantity_returned"] for r in returns if r["return_date"].startswith(month))
        })

    # monthly usage
    monthly_usage = []
    for month in months:
        monthly_usage.append({
            "month": month,
            "amount": sum(i["quantity_issued"] for i in issues if i["issue_date"].startswith(month))
        })

    # monthly purchases
    monthly_purchases = []
    for month in months:
        monthly_purchases.append({
            "month": month,
            "amount": sum(p["quantity"] * float(p["price"] or 0) for p in purchases if p["purchase_date"].startswith(month))
        })

    # department usage
    department_usage = []
    for d in departments:
        department_usage.append({
            "label": d["name"],
            "quantity": sum(i["quantity_issued"] for i in issues if i["department_id"] == d["id"])
        })

    # item usage count
    item_usage = {}
    for i in issues:
        item_id = i["item_id"]
        item_usage[item_id] = item_usage.get(item_id, 0) + i["quantity_issued"]

    item_name_by_id = {item["id"]: item["name"] for item in items}
    usage_entries = []
    for item_id, qty in item_usage.items():
        usage_entries.append({
            "label": item_name_by_id.get(item_id, "Unknown"),
            "quantity": qty
        })
    usage_entries.sort(key=lambda x: x["quantity"], reverse=True)

    top_used_items = usage_entries[:5]
    least_used_items = list(reversed(usage_entries))[:5]

    return jsonify({
        "inventoryValue": inventory_value,
        "stockMovement": stock_movement,
        "monthlyUsage": monthly_usage,
        "departmentUsage": department_usage,
        "topUsedItems": top_used_items,
        "leastUsedItems": least_used_items,
        "monthlyPurchases": monthly_purchases
    })
# 
# # Reports Routes (Disabled)
@app.route("/api/reports/movements", methods=["GET"])
@require_auth
def report_movements():
    m_type = request.args.get("type")
    date_from = request.args.get("dateFrom")
    date_to = request.args.get("dateTo")
    
    records = []
    conn = get_db_connection()
    
    if not m_type or m_type == "purchase":
        q = """
            SELECT p.id, i.name as itemName, s.name as counterparty, p.quantity, p.purchase_date as date
            FROM purchases p
            INNER JOIN inventory_items i ON p.item_id = i.id
            INNER JOIN suppliers s ON p.supplier_id = s.id
            WHERE 1=1
        """
        params = []
        if date_from:
            q += " AND p.purchase_date >= ?"
            params.append(date_from)
        if date_to:
            q += " AND p.purchase_date <= ?"
            params.append(date_to)
            
        rows = conn.execute(q, params).fetchall()
        for r in rows:
            rec = dict(r)
            rec["type"] = "purchase"
            rec["performedBy"] = None
            records.append(rec)
            
    if not m_type or m_type == "issue":
        q = """
            SELECT t.id, i.name as itemName, d.name as counterparty, t.quantity_issued as quantity, t.issue_date as date, t.receiver_name as performedBy
            FROM issue_transactions t
            INNER JOIN inventory_items i ON t.item_id = i.id
            INNER JOIN departments d ON t.department_id = d.id
            WHERE 1=1
        """
        params = []
        if date_from:
            q += " AND t.issue_date >= ?"
            params.append(date_from)
        if date_to:
            q += " AND t.issue_date <= ?"
            params.append(date_to)
            
        rows = conn.execute(q, params).fetchall()
        for r in rows:
            rec = dict(r)
            rec["type"] = "issue"
            records.append(rec)
            
    if not m_type or m_type == "return":
        q = """
            SELECT r.id, i.name as itemName, d.name as counterparty, r.quantity_returned as quantity, r.return_date as date
            FROM return_transactions r
            INNER JOIN inventory_items i ON r.item_id = i.id
            INNER JOIN departments d ON r.department_id = d.id
            WHERE 1=1
        """
        params = []
        if date_from:
            q += " AND r.return_date >= ?"
            params.append(date_from)
        if date_to:
            q += " AND r.return_date <= ?"
            params.append(date_to)
            
        rows = conn.execute(q, params).fetchall()
        for r in rows:
            rec = dict(r)
            rec["type"] = "return"
            rec["performedBy"] = None
            records.append(rec)
            
    conn.close()
    
    # Sort by date desc
    records.sort(key=lambda x: x["date"], reverse=True)
    return jsonify(records)

@app.route("/api/reports/low-stock", methods=["GET"])
@require_auth
def report_low_stock():
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT i.*, c.name as categoryName, s.name as supplierName
        FROM inventory_items i
        LEFT JOIN categories c ON i.category_id = c.id
        LEFT JOIN suppliers s ON i.supplier_id = s.id
        WHERE i.deleted_at IS NULL
    """).fetchall()
    conn.close()
    
    low_stock = []
    for r in rows:
        item = dict(r)
        
        # Mapping to API camelCase format
        item["categoryId"] = item.pop("category_id")
        item["itemCode"] = item.pop("item_code")
        item["supplierId"] = item.pop("supplier_id")
        item["purchaseDate"] = item.pop("purchase_date")
        item["purchasePrice"] = float(item.pop("purchase_price")) if item.get("purchase_price") else None
        item["totalPurchased"] = item.pop("total_purchased")
        item["totalIssued"] = item.pop("total_issued")
        item["totalReturned"] = item.pop("total_returned")
        item["availableStock"] = item.pop("available_stock")
        item["minimumStock"] = item.pop("minimum_stock")
        item["maximumStock"] = item.pop("maximum_stock")
        item["imageUrl"] = item.pop("image_url")
        item["createdAt"] = item.pop("created_at")
        item["updatedAt"] = item.pop("updated_at")
        item["deletedAt"] = item.pop("deleted_at")
        
        item["categoryName"] = item["categoryName"] or "Uncategorized"
        item["status"] = compute_status(item["availableStock"], item["minimumStock"])
        
        if item["status"] != "in_stock":
            low_stock.append(item)
            
    return jsonify(low_stock)
# 
# # Notifications Routes (Disabled)
@app.route("/api/notifications", methods=["GET"])
@require_auth
def get_notifications():
    unread_only = request.args.get("unreadOnly", "false").lower() == "true"
    
    conn = get_db_connection()
    if unread_only:
        rows = conn.execute("SELECT * FROM notifications WHERE is_read = 0 ORDER BY created_at DESC").fetchall()
    else:
        rows = conn.execute("SELECT * FROM notifications ORDER BY created_at DESC").fetchall()
    conn.close()
    
    results = []
    for r in rows:
        n = dict(r)
        n["isRead"] = n.pop("is_read") == 1
        n["createdAt"] = n.pop("created_at")
        results.append(n)
    return jsonify(results)

@app.route("/api/notifications/<int:n_id>/read", methods=["PATCH"])
@require_auth
def mark_notification_read(n_id):
    conn = get_db_connection()
    existing = conn.execute("SELECT id FROM notifications WHERE id = ?", (n_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({"error": "Notification not found"}), 404
        
    conn.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (n_id,))
    conn.commit()
    
    updated = conn.execute("SELECT * FROM notifications WHERE id = ?", (n_id,)).fetchone()
    conn.close()
    
    n = dict(updated)
    n["isRead"] = n.pop("is_read") == 1
    n["createdAt"] = n.pop("created_at")
    return jsonify(n)

@app.route("/api/notifications/mark-all-read", methods=["POST"])
@require_auth
def mark_all_notifications_read():
    conn = get_db_connection()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE is_read = 0")
    conn.commit()
    conn.close()
    return jsonify({"message": "All notifications marked as read"})
# 
# # Audit Logs Route (Disabled)
@app.route("/api/audit-logs", methods=["GET"])
@require_auth
def audit_logs():
    entity_type = request.args.get("entityType")
    action = request.args.get("action")
    date_from = request.args.get("dateFrom")
    date_to = request.args.get("dateTo")
    
    query = "SELECT * FROM activity_logs WHERE 1=1"
    params = []
    
    if entity_type:
        query += " AND entity_type = ?"
        params.append(entity_type)
    if action:
        query += " AND action = ?"
        params.append(action)
    if date_from:
        query += " AND created_at >= ?"
        params.append(date_from)
    if date_to:
        query += " AND created_at <= ?"
        params.append(date_to)
        
    query += " ORDER BY created_at DESC"
    
    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    results = []
    for r in rows:
        log = dict(r)
        log["userId"] = log.pop("user_id")
        log["entityType"] = log.pop("entity_type")
        log["entityId"] = log.pop("entity_id")
        log["previousQuantity"] = log.pop("previous_quantity")
        log["newQuantity"] = log.pop("new_quantity")
        log["ipAddress"] = log.pop("ip_address")
        log["userAgent"] = log.pop("user_agent")
        log["createdAt"] = log.pop("created_at")
        results.append(log)
        
    return jsonify(results)

# Catch-all Route for Wouter SPA Frontend Router
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    if path.startswith("api/"):
        return jsonify({"error": "Not Found"}), 404
        
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
        
    return send_from_directory(app.static_folder, "index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
