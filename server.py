from fastapi import FastAPI, HTTPException, Header, Query, Form, Request
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, List
import random
import time
import re
import asyncio
from datetime import datetime
from collections import deque
import db

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Queue for MicroPython device to pull pending OTP send instructions
pending_otp_sends = deque()

# OTP expiry time in seconds (2 minutes)
OTP_EXPIRY_SECONDS = 120

# Regex for basic Bangladesh phone number validation (starting with 01 and 11 digits)
BD_PHONE_REGEX = re.compile(r'^01[3-9]\d{8}$')
# Regex for Bangladesh phone with country code
BD_PHONE_WITH_COUNTRY_REGEX = re.compile(r'^8801[3-9]\d{8}$')

# Admin credentials (in production, use environment variables)
ADMIN_PASSWORD = "hungama"  # Change this in production

# --- Pydantic Models ---

class SMSRequest(BaseModel):
    msg: str
    to: str
    schedule: Optional[str] = None
    sender_id: Optional[str] = None
    content_id: Optional[str] = None

class OTPVerification(BaseModel):
    phone_number: str
    otp_code: str

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

@app.get("/api/sendsms")
@app.post("/api/sendsms")
async def api_sendsms(
    request: Request,
    api_key: Optional[str] = Query(None),
    msg: Optional[str] = Query(None),
    to: Optional[str] = Query(None),
    schedule: Optional[str] = Query(None),
    sender_id: Optional[str] = Query(None),
    content_id: Optional[str] = Query(None),
    x_api_key: Optional[str] = Header(None)
):
    """
    API endpoint for sending SMS.
    Matches api.sms.net.bd structure.
    Parameters: api_key, msg, to, schedule (optional), sender_id (optional), content_id (optional)
    """
    # Get API key from query parameter or header
    final_api_key = api_key or x_api_key
    if not final_api_key or not db.verify_api_key(final_api_key):
        raise HTTPException(status_code=401, detail={"error": 1, "msg": "Invalid or missing API key"})
    
    # Check SMS balance
    balance_valid, balance_message = db.check_sms_balance(final_api_key)
    if not balance_valid:
        raise HTTPException(status_code=402, detail={"error": 1, "msg": balance_message})
    
    # Get parameters from query (GET) or JSON (POST)
    if request.method == "POST":
        try:
            data = await request.json()
        except:
            data = {}
        msg = data.get('msg') or msg
        to = data.get('to') or to
        schedule = data.get('schedule') or schedule
        sender_id = data.get('sender_id') or sender_id
        content_id = data.get('content_id') or content_id
    
    # Validate required parameters
    if not msg:
        raise HTTPException(status_code=400, detail={"error": 1, "msg": "Message (msg) is required"})
    
    if not to:
        raise HTTPException(status_code=400, detail={"error": 1, "msg": "Recipient number (to) is required"})
    
    # Handle multiple recipients (comma-separated)
    phone_numbers = [p.strip() for p in to.split(',')]
    
    # Validate all phone numbers
    for phone_number in phone_numbers:
        normalized_phone = normalize_phone_number(phone_number)
        if not is_valid_bd_phone(normalized_phone):
            raise HTTPException(status_code=400, detail={"error": 1, "msg": f"Invalid phone number format: {phone_number}"})
    
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
                raise HTTPException(status_code=400, detail={"error": 1, "msg": "Schedule time must be in the future"})
        except ValueError:
            raise HTTPException(status_code=400, detail={"error": 1, "msg": "Invalid schedule format. Use Y-m-d H:i:s (e.g., 2025-11-13 22:54:50)"})
    
    # Normalize phone numbers
    normalized_numbers = [normalize_phone_number(p) for p in phone_numbers]
    
    # Create SMS request
    status = "Scheduled" if scheduled_time else "Pending"
    request_id = db.create_sms_request(final_api_key, normalized_numbers, final_message, status, scheduled_time, sender_id, content_id)
    
    # Send SMS immediately if not scheduled
    if not scheduled_time:
        # Deduct balance before sending
        if not db.deduct_sms_balance(final_api_key):
            raise HTTPException(status_code=500, detail={"error": 1, "msg": "Failed to deduct SMS balance"})
        
        # Send SMS to all recipients and add to device queue
        all_sent = True
        for phone_number in normalized_numbers:
            # Add to device queue for MicroPython device to pull
            pending_otp_sends.append({
                'phone_number': phone_number,
                'message': final_message,
                'otp_code': otp_code if otp_code else None
            })
            
            if send_sms_via_service(phone_number, final_message, final_api_key):
                db.update_recipient_status(request_id, phone_number, "Sent")
            else:
                db.update_recipient_status(request_id, phone_number, "Failed")
                all_sent = False
        
        db.update_sms_request_status(request_id, "Complete" if all_sent else "Partial")
        db.increment_stat('total_otp_requests')
        db.update_api_usage(final_api_key)
        print(f"API: Sent SMS to {to} via API. Request ID: {request_id}. Added to device queue.")
    
    return {
        "error": 0,
        "msg": "Request successfully submitted",
        "data": {
            "request_id": request_id
        }
    }

@app.post("/api/verify_otp")
async def api_verify_otp(
    otp_data: OTPVerification,
    x_api_key: Optional[str] = Header(None)
):
    """
    API endpoint for external servers to verify OTP.
    Requires API key authentication.
    """
    # Check API key
    if not x_api_key or not db.verify_api_key(x_api_key):
        raise HTTPException(status_code=401, detail={"error": "Invalid or missing API key"})
    
    phone_number = otp_data.phone_number
    otp_input = otp_data.otp_code
    
    # Validate inputs
    if not phone_number or not is_valid_bd_phone(phone_number):
        raise HTTPException(status_code=400, detail={"error": "Invalid Bangladesh phone number format"})
    
    if not otp_input:
        raise HTTPException(status_code=400, detail={"error": "OTP code is required"})
    
    # Normalize phone number for lookup (OTPs are stored with normalized numbers)
    normalized_phone = normalize_phone_number(phone_number)
    
    # Update statistics
    db.increment_stat('total_otp_verifications')
    db.update_api_usage(x_api_key)
    
    # Verify OTP
    otp_record = db.get_otp(normalized_phone)
    
    if otp_record and otp_record['otp_code'] == otp_input:
        if otp_record['expiry_time'] > time.time():  # Check if OTP is still valid
            # Delete OTP using the key that was found
            db.delete_otp(normalized_phone)
            db.increment_stat('successful_verifications')
            return {
                "success": True,
                "message": "OTP verified successfully",
                "phone_number": phone_number
            }
        else:
            db.increment_stat('failed_verifications')
            raise HTTPException(status_code=400, detail={"error": "OTP expired"})
    else:
        db.increment_stat('failed_verifications')
        raise HTTPException(status_code=400, detail={"error": "Invalid OTP or phone number"})

# --- MicroPython Device API Route ---

@app.get("/get_pending_otp_send")
async def get_pending_otp_send():
    """
    API endpoint for MicroPython device to poll for pending OTP send instructions.
    Returns one instruction at a time from the queue.
    """
    if pending_otp_sends:
        otp_instruction = pending_otp_sends.popleft()
        print(f"Server: Sending OTP instruction to device: {otp_instruction['phone_number']} with message: {otp_instruction['message']}")
        return {
            "send_otp": True,
            "target_phone_number": otp_instruction['phone_number'],
            "message": otp_instruction['message'],
            "otp_code": otp_instruction.get('otp_code')
        }
    else:
        return {"send_otp": False}

@app.get("/api/report/request/{request_id}/")
async def api_report_request(
    request_id: int,
    api_key: Optional[str] = Query(None)
):
    """
    API endpoint for checking SMS delivery status.
    Matches api.sms.net.bd structure.
    Parameters: api_key (query parameter)
    """
    # Get API key from query parameter
    if not api_key or not db.verify_api_key(api_key):
        raise HTTPException(status_code=401, detail={"error": 1, "msg": "Invalid or missing API key"})
    
    # Check if request exists
    request_data = db.get_sms_request(request_id)
    if not request_data:
        raise HTTPException(status_code=404, detail={"error": 1, "msg": "Request not found"})
    
    # Verify API key matches request
    if request_data["api_key"] != api_key:
        raise HTTPException(status_code=403, detail={"error": 1, "msg": "Unauthorized access to this request"})
    
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
                pending_otp_sends.append({
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
    
    return {
        "error": 0,
        "msg": "Success",
        "data": {
            "request_id": request_id,
            "request_status": request_data["status"],
            "request_charge": request_data["charge"],
            "recipients": recipients
        }
    }

@app.get("/api/user/balance/")
async def api_user_balance(api_key: Optional[str] = Query(None)):
    """
    API endpoint for checking SMS balance.
    Matches api.sms.net.bd structure.
    Parameters: api_key (query parameter)
    """
    # Get API key from query parameter
    if not api_key or not db.verify_api_key(api_key):
        raise HTTPException(status_code=401, detail={"error": 1, "msg": "Invalid or missing API key"})
    
    user_data = db.get_api_key(api_key)
    current_time = time.time()
    
    # Check if balance has expired
    balance_expiry = user_data.get("balance_expiry", 0)
    if balance_expiry < current_time:
        balance = "0.0000"
    else:
        balance = f"{user_data.get('sms_balance', 0):.4f}"
    
    return {
        "error": 0,
        "msg": "Success",
        "data": {
            "balance": balance
        }
    }

# --- Admin Routes ---

@app.get("/admin", response_class=HTMLResponse)
@app.post("/admin")
async def admin_login(request: Request, password: Optional[str] = Form(None)):
    """Admin login page."""
    if request.method == "POST":
        if password == ADMIN_PASSWORD:
            return RedirectResponse(url='/admin/dashboard', status_code=303)
        else:
            return templates.TemplateResponse("admin_login.html", {"request": request, "error": True})
    
    return templates.TemplateResponse("admin_login.html", {"request": request, "error": False})

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
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
    
    return templates.TemplateResponse("admin_dashboard.html", 
                                     {"request": request, "stats": stats, "api_keys": api_keys_data})

@app.post("/admin/create_api_key", response_class=HTMLResponse)
async def create_api_key(
    request: Request,
    username: str = Form(...),
    sms_balance: int = Form(0)
):
    """Create a new API key."""
    if not username:
        return RedirectResponse(url='/admin/dashboard', status_code=303)
    
    api_key = db.create_api_key(username, sms_balance, 30)
    current_time = time.time()
    expiry_date = datetime.fromtimestamp(current_time + (30 * 24 * 60 * 60)).strftime('%Y-%m-%d %H:%M:%S') if sms_balance > 0 else 'No balance'
    
    return templates.TemplateResponse("admin_create_key.html", {
        "request": request,
        "username": username,
        "api_key": api_key,
        "sms_balance": sms_balance,
        "expiry_date": expiry_date
    })

@app.post("/admin/manage_balance", response_class=HTMLResponse)
async def manage_balance(
    request: Request,
    api_key: str = Form(...),
    sms_count: int = Form(0),
    days: int = Form(30)
):
    """Manage SMS balance for API keys."""
    key_data = db.get_api_key(api_key)
    if not key_data:
        return templates.TemplateResponse("admin_manage_balance.html", {
            "request": request,
            "success": False,
            "error_message": "Invalid API key selected."
        })
    
    if db.add_sms_balance(api_key, sms_count, days):
        # Get updated key data
        key_data = db.get_api_key(api_key)
        expiry_date = datetime.fromtimestamp(key_data["balance_expiry"]).strftime('%Y-%m-%d %H:%M:%S')
        
        return templates.TemplateResponse("admin_manage_balance.html", {
            "request": request,
            "success": True,
            "username": key_data["username"],
            "sms_count": sms_count,
            "total_balance": key_data["sms_balance"],
            "expiry_date": expiry_date
        })
    else:
        return templates.TemplateResponse("admin_manage_balance.html", {
            "request": request,
            "success": False,
            "error_message": "Failed to add SMS balance."
        })

@app.post("/admin/test_otp", response_class=HTMLResponse)
async def test_otp(request: Request, phone_number: str = Form(...)):
    """Generate test OTP for admin testing."""
    if not phone_number or not is_valid_bd_phone(phone_number):
        return templates.TemplateResponse("admin_test_otp.html", {
            "request": request,
            "success": False,
            "error_message": "Invalid phone number format."
        })
    
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
        
        return templates.TemplateResponse("admin_test_otp.html", {
            "request": request,
            "success": True,
            "phone_number": normalized_phone,
            "otp_code": test_otp_code,
            "expiry_date": expiry_date
        })
    else:
        return templates.TemplateResponse("admin_test_otp.html", {
            "request": request,
            "success": False,
            "error_message": "Failed to send test SMS."
        })

@app.post("/admin/reset_usage", response_class=HTMLResponse)
async def reset_usage(request: Request, api_key: str = Form(...)):
    """Reset API key usage statistics."""
    key_data = db.get_api_key(api_key)
    if not key_data:
        return templates.TemplateResponse("admin_action_result.html", {
            "request": request,
            "success": False,
            "action_title": "Error",
            "error_message": "Invalid API key selected."
        })
    
    if db.reset_api_key_usage(api_key):
        return templates.TemplateResponse("admin_action_result.html", {
            "request": request,
            "success": True,
            "action_title": "Usage Reset",
            "username": key_data["username"],
            "status_message": "Usage count has been reset to 0"
        })
    else:
        return templates.TemplateResponse("admin_action_result.html", {
            "request": request,
            "success": False,
            "action_title": "Error",
            "error_message": "Failed to reset usage statistics."
        })

@app.post("/admin/ban_user", response_class=HTMLResponse)
async def ban_user_route(request: Request, api_key: str = Form(...)):
    """Ban a user."""
    key_data = db.get_api_key(api_key)
    if not key_data:
        return templates.TemplateResponse("admin_action_result.html", {
            "request": request,
            "success": False,
            "action_title": "Error",
            "error_message": "Invalid API key selected."
        })
    
    if db.ban_user(api_key):
        return templates.TemplateResponse("admin_action_result.html", {
            "request": request,
            "success": True,
            "action_title": "User Banned",
            "username": key_data["username"],
            "status_message": "User has been banned. They cannot use the API."
        })
    else:
        return templates.TemplateResponse("admin_action_result.html", {
            "request": request,
            "success": False,
            "action_title": "Error",
            "error_message": "Failed to ban user."
        })

@app.post("/admin/unban_user", response_class=HTMLResponse)
async def unban_user_route(request: Request, api_key: str = Form(...)):
    """Unban a user."""
    key_data = db.get_api_key(api_key)
    if not key_data:
        return templates.TemplateResponse("admin_action_result.html", {
            "request": request,
            "success": False,
            "action_title": "Error",
            "error_message": "Invalid API key selected."
        })
    
    if db.unban_user(api_key):
        return templates.TemplateResponse("admin_action_result.html", {
            "request": request,
            "success": True,
            "action_title": "User Unbanned",
            "username": key_data["username"],
            "status_message": "User has been unbanned. They can use the API if they have balance."
        })
    else:
        return templates.TemplateResponse("admin_action_result.html", {
            "request": request,
            "success": False,
            "action_title": "Error",
            "error_message": "Failed to unban user."
        })

@app.post("/admin/delete_user", response_class=HTMLResponse)
async def delete_user_route(request: Request, api_key: str = Form(...)):
    """Delete a user completely."""
    key_data = db.get_api_key(api_key)
    if not key_data:
        return templates.TemplateResponse("admin_action_result.html", {
            "request": request,
            "success": False,
            "action_title": "Error",
            "error_message": "Invalid API key selected."
        })
    
    username = key_data["username"]
    
    if db.delete_user(api_key):
        return templates.TemplateResponse("admin_action_result.html", {
            "request": request,
            "success": True,
            "action_title": "User Deleted",
            "username": username,
            "status_message": "User has been completely deleted from the system."
        })
    else:
        return templates.TemplateResponse("admin_action_result.html", {
            "request": request,
            "success": False,
            "action_title": "Error",
            "error_message": "Failed to delete user."
        })

# --- 404 Route ---

@app.get("/{path:path}")
async def catch_all(path: str):
    """Return 404 for all routes except API and admin routes."""
    raise HTTPException(status_code=404, detail="Not found")

# --- Startup Event ---

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    db.init_db()
    db.cleanup_expired_otps()

if __name__ == '__main__':
    import uvicorn
    # Set host to '0.0.0.0' to make it accessible from other devices on the network
    uvicorn.run(app, host='0.0.0.0', port=5000)
