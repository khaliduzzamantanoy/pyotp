from flask import Flask, request, jsonify, render_template_string, redirect, url_for
import random
import time
import re
import queue # To store pending OTP requests for the MicroPython device

app = Flask(__name__)

# In-memory storage for OTPs: {phone_number: (otp_code, expiry_timestamp)}
otp_store = {}
# Queue for MicroPython device to pull pending OTP send instructions
# Each item: {'phone_number': '...', 'otp_code': '...'}
pending_otp_sends = queue.Queue()

# OTP expiry time in seconds (2 minutes)
OTP_EXPIRY_SECONDS = 120

# Regex for basic Bangladesh phone number validation (starting with 01 and 11 digits)
BD_PHONE_REGEX = re.compile(r'^01[3-9]\d{8}$')

# --- Utility Functions ---

def generate_otp():
    """Generates a 6-digit random OTP."""
    return str(random.randint(100000, 999999))

def is_valid_bd_phone(phone_number):
    """Checks if the phone number is a valid Bangladesh format."""
    return BD_PHONE_REGEX.match(phone_number) is not None

# --- Web Frontend Routes ---

@app.route('/')
def index():
    """Main homepage with OTP request and verification forms."""
    message = request.args.get('message', '')
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>OTP Test Server</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: sans-serif; margin: 20px; }
                form { margin-bottom: 30px; padding: 20px; border: 1px solid #ccc; border-radius: 8px; max-width: 400px; }
                input[type="text"], button { width: 100%; padding: 10px; margin-bottom: 10px; border-radius: 4px; border: 1px solid #ddd; box-sizing: border-box; }
                button { background-color: #4CAF50; color: white; border: none; cursor: pointer; }
                button:hover { opacity: 0.9; }
                .message { padding: 10px; border-radius: 4px; margin-top: 10px; }
                .success { background-color: #d4edda; color: #155724; border-color: #c3e6cb; }
                .error { background-color: #f8d7da; color: #721c24; border-color: #f5c6cb; }
                h2 { color: #333; }
            </style>
        </head>
        <body>
            <h2>Request OTP</h2>
            <form action="/request_otp" method="post">
                <label for="phone_request">Phone Number (e.g., 01712345678):</label><br>
                <input type="text" id="phone_request" name="phone" placeholder="01XXXXXXXXX" required pattern="^01[3-9]\\d{8}$" title="Must be a valid Bangladesh phone number (01X XXXXXXXX)"><br>
                <button type="submit">Request OTP</button>
            </form>

            <h2>Verify OTP</h2>
            <form action="/verify_otp" method="post">
                <label for="phone_verify">Phone Number:</label><br>
                <input type="text" id="phone_verify" name="phone" placeholder="01XXXXXXXXX" required pattern="^01[3-9]\\d{8}$" title="Must be a valid Bangladesh phone number (01X XXXXXXXX)"><br>
                <label for="otp_verify">OTP:</label><br>
                <input type="text" id="otp_verify" name="otp" required><br>
                <button type="submit">Verify OTP</button>
            </form>

            {% if message %}
                <p class="message {{ 'success' if 'Success' in message else 'error' }}">{{ message }}</p>
            {% endif %}
        </body>
        </html>
    ''', message=message)

@app.route('/request_otp', methods=['POST'])
def request_otp_web():
    """Handles OTP request from the web frontend."""
    phone = request.form['phone']
    if not is_valid_bd_phone(phone):
        return redirect(url_for('index', message='Error: Invalid Bangladesh phone number format.'))

    otp_code = generate_otp()
    expiry_time = time.time() + OTP_EXPIRY_SECONDS
    otp_store[phone] = (otp_code, expiry_time)

    # Add this OTP request to the queue for the MicroPython device to pick up
    pending_otp_sends.put({'phone_number': phone, 'otp_code': otp_code})

    print(f"Server: Generated OTP {otp_code} for {phone}. Added to send queue.")
    return redirect(url_for('index', message=f'Success: OTP requested for {phone}. Check your device console for send status.'))

@app.route('/verify_otp', methods=['POST'])
def verify_otp_web():
    """Handles OTP verification from the web frontend."""
    phone = request.form['phone']
    otp_input = request.form['otp']

    if not is_valid_bd_phone(phone):
        return redirect(url_for('index', message='Error: Invalid Bangladesh phone number format.'))

    otp_record = otp_store.get(phone)

    if otp_record and otp_record[0] == otp_input:
        if otp_record[1] > time.time(): # Check if OTP is still valid
            del otp_store[phone] # OTP consumed
            return redirect(url_for('index', message='Success: OTP Verified!'))
        else:
            return redirect(url_for('index', message='Error: OTP expired.'))
    else:
        return redirect(url_for('index', message='Error: Invalid OTP or phone number.'))

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
        # print("Server: No pending OTP sends for device.") # Can be noisy
        return jsonify({"send_otp": False})

if __name__ == '__main__':
    # Set host to '0.0.0.0' to make it accessible from other devices on the network
    # For production, set debug=False
    app.run(host='0.0.0.0', port=5000, debug=True)
