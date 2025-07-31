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

# API keys storage: {api_key: {"user": "username", "created": timestamp, "usage_count": 0, "sms_balance": 0, "balance_expiry": timestamp}}
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

def check_sms_balance(api_key):
    """Check if API key has valid SMS balance."""
    if api_key not in api_keys:
        return False, "Invalid API key"
    
    user_data = api_keys[api_key]
    current_time = time.time()
    
    # Check if user is banned
    if user_data.get("banned", False):
        return False, "User account is banned"
    
    # Check if balance has expired
    if user_data.get("balance_expiry", 0) < current_time:
        return False, "SMS balance has expired"
    
    # Check if balance is available
    if user_data.get("sms_balance", 0) <= 0:
        return False, "SMS balance exhausted"
    
    return True, "Balance available"

def deduct_sms_balance(api_key):
    """Deduct one SMS from the balance."""
    if api_key in api_keys:
        if api_keys[api_key].get("sms_balance", 0) > 0:
            api_keys[api_key]["sms_balance"] -= 1
            return True
    return False

def add_sms_balance(api_key, sms_count, days=30):
    """Add SMS balance to an API key."""
    if api_key in api_keys:
        current_balance = api_keys[api_key].get("sms_balance", 0)
        current_expiry = api_keys[api_key].get("balance_expiry", 0)
        current_time = time.time()
        
        # If current balance is expired, start fresh
        if current_expiry < current_time:
            api_keys[api_key]["sms_balance"] = sms_count
            api_keys[api_key]["balance_expiry"] = current_time + (days * 24 * 60 * 60)
        else:
            # Extend existing balance
            api_keys[api_key]["sms_balance"] += sms_count
            api_keys[api_key]["balance_expiry"] = max(current_expiry, current_time) + (days * 24 * 60 * 60)
        
        return True
    return False

def reset_api_key(api_key):
    """Reset API key usage statistics."""
    if api_key in api_keys:
        api_keys[api_key]["usage_count"] = 0
        return True
    return False

def ban_user(api_key):
    """Ban a user by setting their balance to 0 and expiry to past."""
    if api_key in api_keys:
        api_keys[api_key]["sms_balance"] = 0
        api_keys[api_key]["balance_expiry"] = 0
        api_keys[api_key]["banned"] = True
        return True
    return False

def unban_user(api_key):
    """Unban a user by removing banned flag."""
    if api_key in api_keys:
        api_keys[api_key]["banned"] = False
        return True
    return False

def delete_user(api_key):
    """Delete a user completely."""
    if api_key in api_keys:
        del api_keys[api_key]
        return True
    return False

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
    
    # Check SMS balance
    balance_valid, balance_message = check_sms_balance(api_key)
    if not balance_valid:
        return jsonify({"error": balance_message}), 402  # Payment Required
    
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
    
    # Deduct SMS balance and update statistics
    if deduct_sms_balance(api_key):
        usage_stats["total_otp_requests"] += 1
        update_api_usage(api_key)
        print(f"API: Generated OTP {otp_code} for {phone_number} via API. Added to send queue.")
        
        return jsonify({
            "success": True,
            "message": f"OTP {otp_code} generated for {phone_number}",
            "phone_number": phone_number,
            "otp_code": otp_code,
            "expires_in": OTP_EXPIRY_SECONDS,
            "remaining_balance": api_keys[api_key].get("sms_balance", 0)
        })
    else:
        return jsonify({"error": "Failed to deduct SMS balance"}), 500

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
                <th>SMS Balance</th>
                <th>Balance Expiry</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
            {''.join([f'''
            <tr>
                <td>
                    <span id="api_key_{api_key[:10]}">{api_key[:20]}...</span>
                    <button onclick="copyToClipboard('{api_key}')" style="font-size: 10px; padding: 2px 5px;">Copy</button>
                </td>
                <td>{details["user"]}</td>
                <td>{datetime.fromtimestamp(details["created"]).strftime('%Y-%m-%d %H:%M:%S')}</td>
                <td>{details["usage_count"]}</td>
                <td>{details.get("sms_balance", 0)}</td>
                <td>{datetime.fromtimestamp(details.get("balance_expiry", 0)).strftime('%Y-%m-%d %H:%M:%S') if details.get("balance_expiry", 0) > 0 else 'No balance'}</td>
                <td>{'Banned' if details.get("banned", False) else ('Active' if details.get("balance_expiry", 0) > time.time() and details.get("sms_balance", 0) > 0 else 'Inactive')}</td>
                <td>
                    <form method="post" action="/admin/reset_usage" style="display: inline;">
                        <input type="hidden" name="api_key" value="{api_key}">
                        <button type="submit" style="font-size: 10px; padding: 2px 5px; background-color: #ff9800;">Reset</button>
                    </form>
                    <form method="post" action="/admin/ban_user" style="display: inline;">
                        <input type="hidden" name="api_key" value="{api_key}">
                        <button type="submit" style="font-size: 10px; padding: 2px 5px; background-color: #f44336;">Ban</button>
                    </form>
                    <form method="post" action="/admin/unban_user" style="display: inline;">
                        <input type="hidden" name="api_key" value="{api_key}">
                        <button type="submit" style="font-size: 10px; padding: 2px 5px; background-color: #4CAF50;">Unban</button>
                    </form>
                    <form method="post" action="/admin/delete_user" style="display: inline;" onsubmit="return confirm('Are you sure you want to delete this user? This action cannot be undone.')">
                        <input type="hidden" name="api_key" value="{api_key}">
                        <button type="submit" style="font-size: 10px; padding: 2px 5px; background-color: #d32f2f;">Delete</button>
                    </form>
                </td>
            </tr>
            ''' for api_key, details in api_keys.items()])}
        </table>
        
        <h3>Create New API Key</h3>
        <form action="/admin/create_api_key" method="post">
            <input type="text" name="username" placeholder="Username" required><br><br>
            <input type="number" name="sms_balance" placeholder="Initial SMS Balance" min="0" value="0"><br><br>
            <button type="submit">Create API Key</button>
        </form>
        
        <h3>Manage SMS Balance</h3>
        <form action="/admin/manage_balance" method="post">
            <select name="api_key" required>
                <option value="">Select API Key</option>
                {''.join([f'<option value="{api_key}">{details["user"]} ({api_key[:20]}...)</option>' for api_key, details in api_keys.items()])}
            </select><br><br>
            <input type="number" name="sms_count" placeholder="SMS Count" min="1" required><br><br>
            <input type="number" name="days" placeholder="Days (default 30)" min="1" value="30"><br><br>
            <button type="submit">Add SMS Balance</button>
        </form>
        
        <h3>Test OTP System</h3>
        <form action="/admin/test_otp" method="post">
            <input type="text" name="phone_number" placeholder="Phone Number (e.g., 01712345678)" pattern="^01[3-9]\\d{8}$" required><br><br>
            <button type="submit">Generate Test OTP</button>
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
        
        <script>
        function copyToClipboard(text) {{
            navigator.clipboard.writeText(text).then(function() {{
                alert('API Key copied to clipboard!');
            }}, function(err) {{
                console.error('Could not copy text: ', err);
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                alert('API Key copied to clipboard!');
            }});
        }}
        </script>
    ''')

@app.route('/admin/create_api_key', methods=['POST'])
def create_api_key():
    """Create a new API key."""
    username = request.form.get('username')
    sms_balance = int(request.form.get('sms_balance', 0))
    if not username:
        return redirect('/admin/dashboard')
    
    api_key = generate_api_key()
    current_time = time.time()
    api_keys[api_key] = {
        "user": username,
        "created": current_time,
        "usage_count": 0,
        "sms_balance": sms_balance,
        "balance_expiry": current_time + (30 * 24 * 60 * 60) if sms_balance > 0 else 0
    }
    
    return render_admin_template(f'''
        <h2>API Key Created</h2>
        <p><strong>Username:</strong> {username}</p>
        <p><strong>API Key:</strong> {api_key}</p>
        <p><strong>Initial SMS Balance:</strong> {sms_balance}</p>
        <p><strong>Balance Expiry:</strong> {datetime.fromtimestamp(current_time + (30 * 24 * 60 * 60)).strftime('%Y-%m-%d %H:%M:%S') if sms_balance > 0 else 'No balance'}</p>
        <p><strong>Warning:</strong> Save this API key securely. It won't be shown again.</p>
        <br>
        <a href="/admin/dashboard">Back to Dashboard</a>
    ''')

@app.route('/admin/manage_balance', methods=['POST'])
def manage_balance():
    """Manage SMS balance for API keys."""
    api_key = request.form.get('api_key')
    sms_count = int(request.form.get('sms_count', 0))
    days = int(request.form.get('days', 30))
    
    if not api_key or api_key not in api_keys:
        return render_admin_template('''
            <h2>Error</h2>
            <p>Invalid API key selected.</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')
    
    if add_sms_balance(api_key, sms_count, days):
        user_data = api_keys[api_key]
        expiry_date = datetime.fromtimestamp(user_data["balance_expiry"]).strftime('%Y-%m-%d %H:%M:%S')
        
        return render_admin_template(f'''
            <h2>SMS Balance Added</h2>
            <p><strong>User:</strong> {user_data["user"]}</p>
            <p><strong>SMS Added:</strong> {sms_count}</p>
            <p><strong>Total Balance:</strong> {user_data["sms_balance"]}</p>
            <p><strong>Expiry Date:</strong> {expiry_date}</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')
    else:
        return render_admin_template('''
            <h2>Error</h2>
            <p>Failed to add SMS balance.</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')

@app.route('/admin/test_otp', methods=['POST'])
def test_otp():
    """Generate test OTP for admin testing."""
    phone_number = request.form.get('phone_number')
    
    if not phone_number or not is_valid_bd_phone(phone_number):
        return render_admin_template('''
            <h2>Error</h2>
            <p>Invalid phone number format.</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')
    
    # Generate test OTP
    test_otp_code = generate_otp()
    expiry_time = time.time() + OTP_EXPIRY_SECONDS
    otp_store[phone_number] = (test_otp_code, expiry_time)
    
    # Add to pending sends queue
    pending_otp_sends.put({'phone_number': phone_number, 'otp_code': test_otp_code})
    
    # Update statistics
    usage_stats["total_otp_requests"] += 1
    
    expiry_date = datetime.fromtimestamp(expiry_time).strftime('%Y-%m-%d %H:%M:%S')
    
    return render_admin_template(f'''
        <h2>Test OTP Generated</h2>
        <p><strong>Phone Number:</strong> {phone_number}</p>
        <p><strong>OTP Code:</strong> {test_otp_code}</p>
        <p><strong>Expires:</strong> {expiry_date}</p>
        <p><strong>Status:</strong> Added to device queue for SMS sending</p>
        <br>
        <a href="/admin/dashboard">Back to Dashboard</a>
    ''')

@app.route('/admin/reset_usage', methods=['POST'])
def reset_usage():
    """Reset API key usage statistics."""
    api_key = request.form.get('api_key')
    
    if not api_key or api_key not in api_keys:
        return render_admin_template('''
            <h2>Error</h2>
            <p>Invalid API key selected.</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')
    
    if reset_api_key(api_key):
        user_data = api_keys[api_key]
        return render_admin_template(f'''
            <h2>Usage Reset</h2>
            <p><strong>User:</strong> {user_data["user"]}</p>
            <p><strong>Status:</strong> Usage count has been reset to 0</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')
    else:
        return render_admin_template('''
            <h2>Error</h2>
            <p>Failed to reset usage statistics.</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')

@app.route('/admin/ban_user', methods=['POST'])
def ban_user_route():
    """Ban a user."""
    api_key = request.form.get('api_key')
    
    if not api_key or api_key not in api_keys:
        return render_admin_template('''
            <h2>Error</h2>
            <p>Invalid API key selected.</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')
    
    if ban_user(api_key):
        user_data = api_keys[api_key]
        return render_admin_template(f'''
            <h2>User Banned</h2>
            <p><strong>User:</strong> {user_data["user"]}</p>
            <p><strong>Status:</strong> User has been banned. They cannot use the API.</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')
    else:
        return render_admin_template('''
            <h2>Error</h2>
            <p>Failed to ban user.</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')

@app.route('/admin/unban_user', methods=['POST'])
def unban_user_route():
    """Unban a user."""
    api_key = request.form.get('api_key')
    
    if not api_key or api_key not in api_keys:
        return render_admin_template('''
            <h2>Error</h2>
            <p>Invalid API key selected.</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')
    
    if unban_user(api_key):
        user_data = api_keys[api_key]
        return render_admin_template(f'''
            <h2>User Unbanned</h2>
            <p><strong>User:</strong> {user_data["user"]}</p>
            <p><strong>Status:</strong> User has been unbanned. They can use the API if they have balance.</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')
    else:
        return render_admin_template('''
            <h2>Error</h2>
            <p>Failed to unban user.</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')

@app.route('/admin/delete_user', methods=['POST'])
def delete_user_route():
    """Delete a user completely."""
    api_key = request.form.get('api_key')
    
    if not api_key or api_key not in api_keys:
        return render_admin_template('''
            <h2>Error</h2>
            <p>Invalid API key selected.</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')
    
    user_data = api_keys[api_key]
    username = user_data["user"]
    
    if delete_user(api_key):
        return render_admin_template(f'''
            <h2>User Deleted</h2>
            <p><strong>User:</strong> {username}</p>
            <p><strong>Status:</strong> User has been completely deleted from the system.</p>
            <br>
            <a href="/admin/dashboard">Back to Dashboard</a>
        ''')
    else:
        return render_admin_template('''
            <h2>Error</h2>
            <p>Failed to delete user.</p>
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
