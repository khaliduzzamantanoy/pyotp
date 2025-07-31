from flask import Flask, request, jsonify, abort, redirect
import random
import time
import re
import queue
import hashlib
import secrets
from datetime import datetime
import json

app = Flask(__name__)

# In-memory storage for OTPs: {phone_number: (otp_code, expiry_timestamp)}
otp_store = {}
# Queue for MicroPython device to pull pending OTP send instructions
pending_otp_sends = queue.Queue()

# OTP expiry time in seconds (2 minutes)
OTP_EXPIRY_SECONDS = 120

# Regex for basic Bangladesh phone number validation (starting with 01 and 11 digits)
BD_PHONE_REGEX = re.compile(r'^01[3-9]\d{8}$')

# Admin credentials (in production, use environment variables)
ADMIN_PASSWORD = "hungama"  # Change this in production

# API keys storage: {api_key: {"user": "username", "created": timestamp, "usage_count": 0}}
api_keys = {}

# Usage statistics
usage_stats = {
    "total_otp_requests": 0,
    "total_otp_verifications": 0,
    "successful_verifications": 0,
    "failed_verifications": 0,
    "api_usage": {}
}

# --- Utility Functions ---

def generate_otp():
    """Generates a 6-digit random OTP."""
    return str(random.randint(100000, 999999))

def is_valid_bd_phone(phone_number):
    """Checks if the phone number is a valid Bangladesh format."""
    return BD_PHONE_REGEX.match(phone_number) is not None

def generate_api_key():
    """Generates a secure API key."""
    return secrets.token_urlsafe(32)

def hash_password(password):
    """Hash password for storage."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_api_key(api_key):
    """Verify if API key exists and is valid."""
    return api_key in api_keys

def update_api_usage(api_key):
    """Update usage statistics for API key."""
    if api_key in api_keys:
        api_keys[api_key]["usage_count"] += 1
        usage_stats["api_usage"][api_key] = usage_stats["api_usage"].get(api_key, 0) + 1

# --- API Routes ---

@app.route('/api/generate_otp', methods=['POST'])
def api_generate_otp():
    """
    API endpoint for external servers to generate OTP.
    Requires API key authentication.
    """
    # Check API key
    api_key = request.headers.get('X-API-Key')
    if not api_key or not verify_api_key(api_key):
        return jsonify({"error": "Invalid or missing API key"}), 401
    
    # Get request data
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    phone_number = data.get('phone_number')
    otp_code = data.get('otp_code')
    
    # Validate phone number
    if not phone_number or not is_valid_bd_phone(phone_number):
        return jsonify({"error": "Invalid Bangladesh phone number format"}), 400
    
    # Validate OTP code (must be provided by user server)
    if not otp_code or not otp_code.isdigit() or len(otp_code) != 6:
        return jsonify({"error": "Invalid OTP code. Must be 6 digits"}), 400
    
    # Store OTP
    expiry_time = time.time() + OTP_EXPIRY_SECONDS
    otp_store[phone_number] = (otp_code, expiry_time)
    
    # Add to pending sends queue
    pending_otp_sends.put({'phone_number': phone_number, 'otp_code': otp_code})
    
    # Update statistics
    usage_stats["total_otp_requests"] += 1
    update_api_usage(api_key)
    
    print(f"API: Generated OTP {otp_code} for {phone_number} via API. Added to send queue.")
    
    return jsonify({
        "success": True,
        "message": f"OTP {otp_code} generated for {phone_number}",
        "phone_number": phone_number,
        "otp_code": otp_code,
        "expires_in": OTP_EXPIRY_SECONDS
    })

@app.route('/api/verify_otp', methods=['POST'])
def api_verify_otp():
    """
    API endpoint for external servers to verify OTP.
    Requires API key authentication.
    """
    # Check API key
    api_key = request.headers.get('X-API-Key')
    if not api_key or not verify_api_key(api_key):
        return jsonify({"error": "Invalid or missing API key"}), 401
    
    # Get request data
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    phone_number = data.get('phone_number')
    otp_input = data.get('otp_code')
    
    # Validate inputs
    if not phone_number or not is_valid_bd_phone(phone_number):
        return jsonify({"error": "Invalid Bangladesh phone number format"}), 400
    
    if not otp_input:
        return jsonify({"error": "OTP code is required"}), 400
    
    # Update statistics
    usage_stats["total_otp_verifications"] += 1
    update_api_usage(api_key)
    
    # Verify OTP
    otp_record = otp_store.get(phone_number)
    
    if otp_record and otp_record[0] == otp_input:
        if otp_record[1] > time.time():  # Check if OTP is still valid
            del otp_store[phone_number]  # OTP consumed
            usage_stats["successful_verifications"] += 1
            return jsonify({
                "success": True,
                "message": "OTP verified successfully",
                "phone_number": phone_number
            })
        else:
            usage_stats["failed_verifications"] += 1
            return jsonify({"error": "OTP expired"}), 400
    else:
        usage_stats["failed_verifications"] += 1
        return jsonify({"error": "Invalid OTP or phone number"}), 400

# --- MicroPython Device API Route ---

@app.route('/get_pending_otp_send', methods=['GET'])
def get_pending_otp_send():
    """
    API endpoint for MicroPython device to poll for pending OTP send instructions.
    Returns one instruction at a time from the queue.
    """
    if not pending_otp_sends.empty():
        otp_instruction = pending_otp_sends.get()
        print(f"Server: Sending OTP instruction to device: {otp_instruction['phone_number']} with OTP {otp_instruction['otp_code']}")
        return jsonify({
            "send_otp": True,
            "target_phone_number": otp_instruction['phone_number'],
            "otp_code": otp_instruction['otp_code']
        })
    else:
        return jsonify({"send_otp": False})

# --- Admin Routes ---

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    """Admin login page."""
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            return redirect('/admin/dashboard')
        else:
            return render_admin_template('''
                <h2>Admin Login</h2>
                <form method="post">
                    <input type="password" name="password" placeholder="Password" required><br><br>
                    <button type="submit">Login</button>
                </form>
                <p style="color: red;">Invalid password</p>
            ''')
    
    return render_admin_template('''
        <h2>Admin Login</h2>
        <form method="post">
            <input type="password" name="password" placeholder="Password" required><br><br>
            <button type="submit">Login</button>
        </form>
    ''')

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard with statistics and API key management."""
    return render_admin_template(f'''
        <h2>Admin Dashboard</h2>
        
        <h3>Usage Statistics</h3>
        <table border="1" style="border-collapse: collapse; width: 100%;">
            <tr><td>Total OTP Requests</td><td>{usage_stats["total_otp_requests"]}</td></tr>
            <tr><td>Total OTP Verifications</td><td>{usage_stats["total_otp_verifications"]}</td></tr>
            <tr><td>Successful Verifications</td><td>{usage_stats["successful_verifications"]}</td></tr>
            <tr><td>Failed Verifications</td><td>{usage_stats["failed_verifications"]}</td></tr>
        </table>
        
        <h3>API Keys</h3>
        <table border="1" style="border-collapse: collapse; width: 100%;">
            <tr>
                <th>API Key</th>
                <th>User</th>
                <th>Created</th>
                <th>Usage Count</th>
            </tr>
            {''.join([f'''
            <tr>
                <td>{api_key[:20]}...</td>
                <td>{details["user"]}</td>
                <td>{datetime.fromtimestamp(details["created"]).strftime('%Y-%m-%d %H:%M:%S')}</td>
                <td>{details["usage_count"]}</td>
            </tr>
            ''' for api_key, details in api_keys.items()])}
        </table>
        
        <h3>Create New API Key</h3>
        <form action="/admin/create_api_key" method="post">
            <input type="text" name="username" placeholder="Username" required><br><br>
            <button type="submit">Create API Key</button>
        </form>
        
        <h3>Documentation</h3>
        <div style="background: #f5f5f5; padding: 15px; border-radius: 5px;">
            <h4>API Endpoints:</h4>
            <p><strong>POST /api/generate_otp</strong> - Generate OTP</p>
            <p><strong>POST /api/verify_otp</strong> - Verify OTP</p>
            <p><strong>GET /get_pending_otp_send</strong> - Get pending OTP for device</p>
            
            <h4>Headers Required:</h4>
            <p><code>X-API-Key: your_api_key</code></p>
            <p><code>Content-Type: application/json</code></p>
            
            <h4>Request Format:</h4>
            <p>Generate OTP: {{"phone_number": "01712345678", "otp_code": "123456"}}</p>
            <p>Verify OTP: {{"phone_number": "01712345678", "otp_code": "123456"}}</p>
        </div>
    ''')

@app.route('/admin/create_api_key', methods=['POST'])
def create_api_key():
    """Create a new API key."""
    username = request.form.get('username')
    if not username:
        return redirect('/admin/dashboard')
    
    api_key = generate_api_key()
    api_keys[api_key] = {
        "user": username,
        "created": time.time(),
        "usage_count": 0
    }
    
    return render_admin_template(f'''
        <h2>API Key Created</h2>
        <p><strong>Username:</strong> {username}</p>
        <p><strong>API Key:</strong> {api_key}</p>
        <p><strong>Warning:</strong> Save this API key securely. It won't be shown again.</p>
        <br>
        <a href="/admin/dashboard">Back to Dashboard</a>
    ''')

def render_admin_template(content):
    """Render admin template with basic styling."""
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>OTP Server Admin</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            table {{ margin: 10px 0; }}
            th, td {{ padding: 8px; text-align: left; }}
            input, button {{ padding: 8px; margin: 5px 0; }}
            button {{ background-color: #4CAF50; color: white; border: none; cursor: pointer; }}
            button:hover {{ opacity: 0.8; }}
        </style>
    </head>
    <body>
        {content}
    </body>
    </html>
    '''

# --- 404 Route ---

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    """Return 404 for all routes except API and admin routes."""
    abort(404)

if __name__ == '__main__':
    # Set host to '0.0.0.0' to make it accessible from other devices on the network
    # For production, set debug=False
    app.run(host='0.0.0.0', port=5000, debug=True)
