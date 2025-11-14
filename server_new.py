from flask import Flask, request, jsonify, abort, redirect, render_template
import random
import time
import re
import queue
from datetime import datetime
import db

app = Flask(__name__)

# Queue for MicroPython device to pull pending OTP send instructions
pending_otp_sends = queue.Queue()

# OTP expiry time in seconds (2 minutes)
OTP_EXPIRY_SECONDS = 120

# Regex for basic Bangladesh phone number validation (starting with 01 and 11 digits)
BD_PHONE_REGEX = re.compile(r'^01[3-9]\d{8}$')
# Regex for Bangladesh phone with country code
BD_PHONE_WITH_COUNTRY_REGEX = re.compile(r'^8801[3-9]\d{8}$')

# Admin credentials (in production, use environment variables)
ADMIN_PASSWORD = "hungama"  # Change this in production

# --- Utility Functions ---

def generate_otp():
    """Generates a 6-digit random OTP."""
    return str(random.randint(100000, 999999))

def is_valid_bd_phone(phone_number):
    """Checks if the phone number is a valid Bangladesh format."""
    # Accept both 01X format and 8801X format
    return BD_PHONE_REGEX.match(phone_number) is not None or BD_PHONE_WITH_COUNTRY_REGEX.match(phone_number) is not None

def normalize_phone_number(phone_number):
    """Normalize phone number to 880 format."""
    if phone_number.startswith('880'):
        return phone_number
    elif phone_number.startswith('01'):
        return '880' + phone_number
    else:
        return phone_number

def send_sms_via_service(phone_number, message, api_key):
    """
    Send SMS via external service.
    This is a placeholder - you can integrate with your actual SMS service here.
    For now, it simulates sending and stores the OTP.
    """
    # In a real implementation, you would call your SMS service API here
    # Example:
    # response = requests.post('https://your-sms-service.com/send', data={
    #     'to': phone_number,
    #     'message': message,
    #     'api_key': api_key
    # })
    # return response.status_code == 200
    
    # For now, we'll simulate successful sending
    # Extract OTP from message if it's an OTP message
    otp_match = re.search(r'\b\d{6}\b', message)
    if otp_match:
        otp_code = otp_match.group()
        expiry_time = time.time() + OTP_EXPIRY_SECONDS
        db.store_otp(phone_number, otp_code, expiry_time)
        print(f"SMS sent to {phone_number}: {message}")
    
    return True  # Simulate success

# --- API Routes ---

@app.route('/api/sendsms', methods=['GET', 'POST'])
def api_sendsms():
    """
    API endpoint for sending SMS.
    Matches api.sms.net.bd structure.
    Parameters: api_key, msg, to, schedule (optional), sender_id (optional), content_id (optional)
    """
    # Get API key from query parameter or header
    api_key = request.args.get('api_key') or request.headers.get('X-API-Key')
    if not api_key or not db.verify_api_key(api_key):
        return jsonify({"error": 1, "msg": "Invalid or missing API key"}), 401
    
    # Check SMS balance
    balance_valid, balance_message = db.check_sms_balance(api_key)
    if not balance_valid:
        return jsonify({"error": 1, "msg": balance_message}), 402
    
    # Get parameters from query (GET) or JSON (POST)
    if request.method == 'GET':
        msg = request.args.get('msg')
        to = request.args.get('to')
        schedule = request.args.get('schedule')
        sender_id = request.args.get('sender_id')
        content_id = request.args.get('content_id')
    else:
        data = request.get_json() or {}
        msg = data.get('msg') or request.args.get('msg')
        to = data.get('to') or request.args.get('to')
        schedule = data.get('schedule') or request.args.get('schedule')
        sender_id = data.get('sender_id') or request.args.get('sender_id')
        content_id = data.get('content_id') or request.args.get('content_id')
    
    # Validate required parameters
    if not msg:
        return jsonify({"error": 1, "msg": "Message (msg) is required"}), 400
    
    if not to:
        return jsonify({"error": 1, "msg": "Recipient number (to) is required"}), 400
    
    # Handle multiple recipients (comma-separated)
    phone_numbers = [p.strip() for p in to.split(',')]
    
    # Validate all phone numbers
    for phone_number in phone_numbers:
        normalized_phone = normalize_phone_number(phone_number)
        if not is_valid_bd_phone(normalized_phone):
            return jsonify({"error": 1, "msg": f"Invalid phone number format: {phone_number}"}), 400
    
    # Use the message as provided by the client (OTP is included in the message)
    final_message = msg
    
    # Try to extract OTP from message if it contains a 6-digit code (for verification purposes)
    otp_match = re.search(r'\b\d{6}\b', msg)
    otp_code = otp_match.group() if otp_match else None
    
    # Process schedule if provided
    scheduled_time = None
    if schedule:
        try:
            scheduled_time = datetime.strptime(schedule, '%Y-%m-%d %H:%M:%S').timestamp()
            if scheduled_time <= time.time():
                return jsonify({"error": 1, "msg": "Schedule time must be in the future"}), 400
        except ValueError:
            return jsonify({"error": 1, "msg": "Invalid schedule format. Use Y-m-d H:i:s (e.g., 2025-11-13 22:54:50)"}), 400
    
    # Normalize phone numbers
    normalized_numbers = [normalize_phone_number(p) for p in phone_numbers]
    
    # Create SMS request
    status = "Scheduled" if scheduled_time else "Pending"
    request_id = db.create_sms_request(api_key, normalized_numbers, final_message, status, scheduled_time, sender_id, content_id)
    
    # Send SMS immediately if not scheduled
    if not scheduled_time:
        # Deduct balance before sending
        if not db.deduct_sms_balance(api_key):
            return jsonify({"error": 1, "msg": "Failed to deduct SMS balance"}), 500
        
        # Send SMS to all recipients and add to device queue
        all_sent = True
        for phone_number in normalized_numbers:
            # Add to device queue for MicroPython device to pull
            pending_otp_sends.put({
                'phone_number': phone_number,
                'message': final_message,
                'otp_code': otp_code if otp_code else None
            })
            
            if send_sms_via_service(phone_number, final_message, api_key):
                db.update_recipient_status(request_id, phone_number, "Sent")
            else:
                db.update_recipient_status(request_id, phone_number, "Failed")
                all_sent = False
        
        db.update_sms_request_status(request_id, "Complete" if all_sent else "Partial")
        db.increment_stat('total_otp_requests')
        db.update_api_usage(api_key)
        print(f"API: Sent SMS to {to} via API. Request ID: {request_id}. Added to device queue.")
    
    return jsonify({
        "error": 0,
        "msg": "Request successfully submitted",
        "data": {
            "request_id": request_id
        }
    })

@app.route('/api/verify_otp', methods=['POST'])
def api_verify_otp():
    """
    API endpoint for external servers to verify OTP.
    Requires API key authentication.
    """
    # Check API key
    api_key = request.headers.get('X-API-Key')
    if not api_key or not db.verify_api_key(api_key):
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
    
    # Normalize phone number for lookup (OTPs are stored with normalized numbers)
    normalized_phone = normalize_phone_number(phone_number)
    
    # Update statistics
    db.increment_stat('total_otp_verifications')
    db.update_api_usage(api_key)
    
    # Verify OTP
    otp_record = db.get_otp(normalized_phone)
    
    if otp_record and otp_record['otp_code'] == otp_input:
        if otp_record['expiry_time'] > time.time():  # Check if OTP is still valid
            # Delete OTP using the key that was found
            db.delete_otp(normalized_phone)
            db.increment_stat('successful_verifications')
            return jsonify({
                "success": True,
                "message": "OTP verified successfully",
                "phone_number": phone_number
            })
        else:
            db.increment_stat('failed_verifications')
            return jsonify({"error": "OTP expired"}), 400
    else:
        db.increment_stat('failed_verifications')
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
        print(f"Server: Sending OTP instruction to device: {otp_instruction['phone_number']} with message: {otp_instruction['message']}")
        return jsonify({
            "send_otp": True,
            "target_phone_number": otp_instruction['phone_number'],
            "message": otp_instruction['message'],
            "otp_code": otp_instruction.get('otp_code')
        })
    else:
        return jsonify({"send_otp": False})

@app.route('/api/report/request/<int:request_id>/', methods=['GET'])
def api_report_request(request_id):
    """
    API endpoint for checking SMS delivery status.
    Matches api.sms.net.bd structure.
    Parameters: api_key (query parameter)
    """
    # Get API key from query parameter
    api_key = request.args.get('api_key')
    if not api_key or not db.verify_api_key(api_key):
        return jsonify({"error": 1, "msg": "Invalid or missing API key"}), 401
    
    # Check if request exists
    request_data = db.get_sms_request(request_id)
    if not request_data:
        return jsonify({"error": 1, "msg": "Request not found"}), 404
    
    # Verify API key matches request
    if request_data["api_key"] != api_key:
        return jsonify({"error": 1, "msg": "Unauthorized access to this request"}), 403
    
    # Check if scheduled request should be sent now
    if request_data.get("scheduled_time") and request_data["scheduled_time"] <= time.time() and request_data["status"] == "Scheduled":
        # Send scheduled SMS
        if db.deduct_sms_balance(api_key):
            # Extract OTP from message if present
            otp_match = re.search(r'\b\d{6}\b', request_data["message"])
            otp_code = otp_match.group() if otp_match else None
            
            all_sent = True
            for phone_number in request_data["phone_numbers"]:
                # Add to device queue for MicroPython device to pull
                pending_otp_sends.put({
                    'phone_number': phone_number,
                    'message': request_data["message"],
                    'otp_code': otp_code
                })
                
                if send_sms_via_service(phone_number, request_data["message"], api_key):
                    db.update_recipient_status(request_id, phone_number, "Sent")
                else:
                    db.update_recipient_status(request_id, phone_number, "Failed")
                    all_sent = False
            
            db.update_sms_request_status(request_id, "Complete" if all_sent else "Partial")
            db.increment_stat('total_otp_requests')
            db.update_api_usage(api_key)
            # Refresh request data
            request_data = db.get_sms_request(request_id)
    
    # Format recipients for response
    recipients = []
    for r in request_data.get('recipients', []):
        recipients.append({
            "number": r['phone_number'],
            "charge": r['charge'],
            "status": r['status']
        })
    
    return jsonify({
        "error": 0,
        "msg": "Success",
        "data": {
            "request_id": request_id,
            "request_status": request_data["status"],
            "request_charge": request_data["charge"],
            "recipients": recipients
        }
    })

@app.route('/api/user/balance/', methods=['GET'])
def api_user_balance():
    """
    API endpoint for checking SMS balance.
    Matches api.sms.net.bd structure.
    Parameters: api_key (query parameter)
    """
    # Get API key from query parameter
    api_key = request.args.get('api_key')
    if not api_key or not db.verify_api_key(api_key):
        return jsonify({"error": 1, "msg": "Invalid or missing API key"}), 401
    
    user_data = db.get_api_key(api_key)
    current_time = time.time()
    
    # Check if balance has expired
    balance_expiry = user_data.get("balance_expiry", 0)
    if balance_expiry < current_time:
        balance = "0.0000"
    else:
        balance = f"{user_data.get('sms_balance', 0):.4f}"
    
    return jsonify({
        "error": 0,
        "msg": "Success",
        "data": {
            "balance": balance
        }
    })

# --- Admin Routes ---

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    """Admin login page."""
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            return redirect('/admin/dashboard')
        else:
            return render_template('admin_login.html', error=True)
    
    return render_template('admin_login.html', error=False)

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard with statistics and API key management."""
    # Get statistics
    stats = db.get_all_stats()
    
    # Get all API keys with formatted data
    api_keys_data = db.get_all_api_keys()
    current_time = time.time()
    
    for key in api_keys_data:
        # Format created date
        key['created_str'] = datetime.fromtimestamp(key['created']).strftime('%Y-%m-%d %H:%M:%S')
        
        # Format balance expiry
        if key['balance_expiry'] > 0:
            key['balance_expiry_str'] = datetime.fromtimestamp(key['balance_expiry']).strftime('%Y-%m-%d %H:%M:%S')
        else:
            key['balance_expiry_str'] = 'No balance'
        
        # Determine status
        if key['banned']:
            key['status'] = 'Banned'
        elif key['balance_expiry'] > current_time and key['sms_balance'] > 0:
            key['status'] = 'Active'
        else:
            key['status'] = 'Inactive'
    
    return render_template('admin_dashboard.html', stats=stats, api_keys=api_keys_data)

@app.route('/admin/create_api_key', methods=['POST'])
def create_api_key():
    """Create a new API key."""
    username = request.form.get('username')
    sms_balance = int(request.form.get('sms_balance', 0))
    if not username:
        return redirect('/admin/dashboard')
    
    api_key = db.create_api_key(username, sms_balance, 30)
    current_time = time.time()
    expiry_date = datetime.fromtimestamp(current_time + (30 * 24 * 60 * 60)).strftime('%Y-%m-%d %H:%M:%S') if sms_balance > 0 else 'No balance'
    
    return render_template('admin_create_key.html', 
                         username=username, 
                         api_key=api_key, 
                         sms_balance=sms_balance,
                         expiry_date=expiry_date)

@app.route('/admin/manage_balance', methods=['POST'])
def manage_balance():
    """Manage SMS balance for API keys."""
    api_key = request.form.get('api_key')
    sms_count = int(request.form.get('sms_count', 0))
    days = int(request.form.get('days', 30))
    
    key_data = db.get_api_key(api_key)
    if not key_data:
        return render_template('admin_manage_balance.html', 
                             success=False, 
                             error_message="Invalid API key selected.")
    
    if db.add_sms_balance(api_key, sms_count, days):
        # Get updated key data
        key_data = db.get_api_key(api_key)
        expiry_date = datetime.fromtimestamp(key_data["balance_expiry"]).strftime('%Y-%m-%d %H:%M:%S')
        
        return render_template('admin_manage_balance.html',
                             success=True,
                             username=key_data["username"],
                             sms_count=sms_count,
                             total_balance=key_data["sms_balance"],
                             expiry_date=expiry_date)
    else:
        return render_template('admin_manage_balance.html',
                             success=False,
                             error_message="Failed to add SMS balance.")

@app.route('/admin/test_otp', methods=['POST'])
def test_otp():
    """Generate test OTP for admin testing."""
    phone_number = request.form.get('phone_number')
    
    if not phone_number or not is_valid_bd_phone(phone_number):
        return render_template('admin_test_otp.html',
                             success=False,
                             error_message="Invalid phone number format.")
    
    # For admin test, we'll generate a test OTP (this is just for testing purposes)
    # In production, OTP comes from client server
    test_otp_code = generate_otp()
    test_message = f"Your OTP code is {test_otp_code}. Valid for 2 minutes."
    
    # Normalize phone number
    normalized_phone = normalize_phone_number(phone_number)
    
    # Send test SMS
    if send_sms_via_service(normalized_phone, test_message, None):
        expiry_time = time.time() + OTP_EXPIRY_SECONDS
        expiry_date = datetime.fromtimestamp(expiry_time).strftime('%Y-%m-%d %H:%M:%S')
        
        # Update statistics
        db.increment_stat('total_otp_requests')
        
        return render_template('admin_test_otp.html',
                             success=True,
                             phone_number=normalized_phone,
                             otp_code=test_otp_code,
                             expiry_date=expiry_date)
    else:
        return render_template('admin_test_otp.html',
                             success=False,
                             error_message="Failed to send test SMS.")

@app.route('/admin/reset_usage', methods=['POST'])
def reset_usage():
    """Reset API key usage statistics."""
    api_key = request.form.get('api_key')
    
    key_data = db.get_api_key(api_key)
    if not key_data:
        return render_template('admin_action_result.html',
                             success=False,
                             action_title="Error",
                             error_message="Invalid API key selected.")
    
    if db.reset_api_key_usage(api_key):
        return render_template('admin_action_result.html',
                             success=True,
                             action_title="Usage Reset",
                             username=key_data["username"],
                             status_message="Usage count has been reset to 0")
    else:
        return render_template('admin_action_result.html',
                             success=False,
                             action_title="Error",
                             error_message="Failed to reset usage statistics.")

@app.route('/admin/ban_user', methods=['POST'])
def ban_user_route():
    """Ban a user."""
    api_key = request.form.get('api_key')
    
    key_data = db.get_api_key(api_key)
    if not key_data:
        return render_template('admin_action_result.html',
                             success=False,
                             action_title="Error",
                             error_message="Invalid API key selected.")
    
    if db.ban_user(api_key):
        return render_template('admin_action_result.html',
                             success=True,
                             action_title="User Banned",
                             username=key_data["username"],
                             status_message="User has been banned. They cannot use the API.")
    else:
        return render_template('admin_action_result.html',
                             success=False,
                             action_title="Error",
                             error_message="Failed to ban user.")

@app.route('/admin/unban_user', methods=['POST'])
def unban_user_route():
    """Unban a user."""
    api_key = request.form.get('api_key')
    
    key_data = db.get_api_key(api_key)
    if not key_data:
        return render_template('admin_action_result.html',
                             success=False,
                             action_title="Error",
                             error_message="Invalid API key selected.")
    
    if db.unban_user(api_key):
        return render_template('admin_action_result.html',
                             success=True,
                             action_title="User Unbanned",
                             username=key_data["username"],
                             status_message="User has been unbanned. They can use the API if they have balance.")
    else:
        return render_template('admin_action_result.html',
                             success=False,
                             action_title="Error",
                             error_message="Failed to unban user.")

@app.route('/admin/delete_user', methods=['POST'])
def delete_user_route():
    """Delete a user completely."""
    api_key = request.form.get('api_key')
    
    key_data = db.get_api_key(api_key)
    if not key_data:
        return render_template('admin_action_result.html',
                             success=False,
                             action_title="Error",
                             error_message="Invalid API key selected.")
    
    username = key_data["username"]
    
    if db.delete_user(api_key):
        return render_template('admin_action_result.html',
                             success=True,
                             action_title="User Deleted",
                             username=username,
                             status_message="User has been completely deleted from the system.")
    else:
        return render_template('admin_action_result.html',
                             success=False,
                             action_title="Error",
                             error_message="Failed to delete user.")

# --- 404 Route ---

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    """Return 404 for all routes except API and admin routes."""
    abort(404)

if __name__ == '__main__':
    # Initialize database
    db.init_db()
    
    # Cleanup expired OTPs periodically
    db.cleanup_expired_otps()
    
    # Set host to '0.0.0.0' to make it accessible from other devices on the network
    # For production, set debug=False
    app.run(host='0.0.0.0', port=5000, debug=True)

