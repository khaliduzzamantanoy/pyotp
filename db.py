import sqlite3
import time
from datetime import datetime
from contextlib import contextmanager

DATABASE = 'otp_server.db'

@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """Initialize the database with required tables."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # API Keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                api_key TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created REAL NOT NULL,
                usage_count INTEGER DEFAULT 0,
                sms_balance INTEGER DEFAULT 0,
                balance_expiry REAL DEFAULT 0,
                banned INTEGER DEFAULT 0
            )
        ''')
        
        # OTPs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS otps (
                phone_number TEXT PRIMARY KEY,
                otp_code TEXT NOT NULL,
                expiry_time REAL NOT NULL
            )
        ''')
        
        # SMS Requests table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sms_requests (
                request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL,
                charge TEXT DEFAULT '0.0000',
                created REAL NOT NULL,
                scheduled_time REAL,
                sender_id TEXT,
                content_id TEXT,
                FOREIGN KEY (api_key) REFERENCES api_keys(api_key)
            )
        ''')
        
        # SMS Recipients table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sms_recipients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL,
                phone_number TEXT NOT NULL,
                charge TEXT DEFAULT '0.0000',
                status TEXT DEFAULT 'Pending',
                FOREIGN KEY (request_id) REFERENCES sms_requests(request_id)
            )
        ''')
        
        # Usage Statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usage_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stat_name TEXT UNIQUE NOT NULL,
                stat_value INTEGER DEFAULT 0
            )
        ''')
        
        # API Usage tracking table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key TEXT UNIQUE NOT NULL,
                usage_count INTEGER DEFAULT 0,
                FOREIGN KEY (api_key) REFERENCES api_keys(api_key)
            )
        ''')
        
        # Initialize default stats if not exists
        default_stats = [
            ('total_otp_requests', 0),
            ('total_otp_verifications', 0),
            ('successful_verifications', 0),
            ('failed_verifications', 0)
        ]
        
        for stat_name, stat_value in default_stats:
            cursor.execute('''
                INSERT OR IGNORE INTO usage_stats (stat_name, stat_value)
                VALUES (?, ?)
            ''', (stat_name, stat_value))
        
        conn.commit()

# API Keys operations
def create_api_key(username, sms_balance=0, days=30):
    """Create a new API key."""
    import secrets
    api_key = secrets.token_urlsafe(32)
    current_time = time.time()
    balance_expiry = current_time + (days * 24 * 60 * 60) if sms_balance > 0 else 0
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO api_keys (api_key, username, created, sms_balance, balance_expiry)
            VALUES (?, ?, ?, ?, ?)
        ''', (api_key, username, current_time, sms_balance, balance_expiry))
    
    return api_key

def get_api_key(api_key):
    """Get API key details."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM api_keys WHERE api_key = ?', (api_key,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None

def verify_api_key(api_key):
    """Verify if API key exists."""
    return get_api_key(api_key) is not None

def check_sms_balance(api_key):
    """Check if API key has valid SMS balance."""
    key_data = get_api_key(api_key)
    if not key_data:
        return False, "Invalid API key"
    
    if key_data['banned']:
        return False, "User account is banned"
    
    current_time = time.time()
    if key_data['balance_expiry'] < current_time:
        return False, "SMS balance has expired"
    
    if key_data['sms_balance'] <= 0:
        return False, "SMS balance exhausted"
    
    return True, "Balance available"

def deduct_sms_balance(api_key):
    """Deduct one SMS from the balance."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE api_keys 
            SET sms_balance = sms_balance - 1 
            WHERE api_key = ? AND sms_balance > 0
        ''', (api_key,))
        return cursor.rowcount > 0

def add_sms_balance(api_key, sms_count, days=30):
    """Add SMS balance to an API key."""
    with get_db() as conn:
        cursor = conn.cursor()
        key_data = get_api_key(api_key)
        if not key_data:
            return False
        
        current_time = time.time()
        current_balance = key_data['sms_balance']
        current_expiry = key_data['balance_expiry']
        
        # If current balance is expired, start fresh
        if current_expiry < current_time:
            new_balance = sms_count
            new_expiry = current_time + (days * 24 * 60 * 60)
        else:
            # Extend existing balance
            new_balance = current_balance + sms_count
            new_expiry = max(current_expiry, current_time) + (days * 24 * 60 * 60)
        
        cursor.execute('''
            UPDATE api_keys 
            SET sms_balance = ?, balance_expiry = ?
            WHERE api_key = ?
        ''', (new_balance, new_expiry, api_key))
        return True

def get_all_api_keys():
    """Get all API keys."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM api_keys ORDER BY created DESC')
        return [dict(row) for row in cursor.fetchall()]

def update_api_usage(api_key):
    """Update usage statistics for API key."""
    with get_db() as conn:
        cursor = conn.cursor()
        # Update usage count in api_keys
        cursor.execute('''
            UPDATE api_keys 
            SET usage_count = usage_count + 1 
            WHERE api_key = ?
        ''', (api_key,))
        
        # Update or insert in api_usage
        cursor.execute('''
            INSERT OR IGNORE INTO api_usage (api_key, usage_count)
            VALUES (?, 0)
        ''', (api_key,))
        cursor.execute('''
            UPDATE api_usage 
            SET usage_count = usage_count + 1 
            WHERE api_key = ?
        ''', (api_key,))

def reset_api_key_usage(api_key):
    """Reset API key usage statistics."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE api_keys 
            SET usage_count = 0 
            WHERE api_key = ?
        ''', (api_key,))

def ban_user(api_key):
    """Ban a user."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE api_keys 
            SET sms_balance = 0, balance_expiry = 0, banned = 1 
            WHERE api_key = ?
        ''', (api_key,))
        return cursor.rowcount > 0

def unban_user(api_key):
    """Unban a user."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE api_keys 
            SET banned = 0 
            WHERE api_key = ?
        ''', (api_key,))
        return cursor.rowcount > 0

def delete_user(api_key):
    """Delete a user completely."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM api_keys WHERE api_key = ?', (api_key,))
        return cursor.rowcount > 0

# OTP operations
def store_otp(phone_number, otp_code, expiry_time):
    """Store OTP in database."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO otps (phone_number, otp_code, expiry_time)
            VALUES (?, ?, ?)
        ''', (phone_number, otp_code, expiry_time))

def get_otp(phone_number):
    """Get OTP for a phone number."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM otps WHERE phone_number = ?', (phone_number,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None

def delete_otp(phone_number):
    """Delete OTP after verification."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM otps WHERE phone_number = ?', (phone_number,))

def cleanup_expired_otps():
    """Remove expired OTPs from database."""
    current_time = time.time()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM otps WHERE expiry_time < ?', (current_time,))

# SMS Request operations
def create_sms_request(api_key, phone_numbers, message, status, scheduled_time=None, sender_id=None, content_id=None):
    """Create a new SMS request."""
    current_time = time.time()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO sms_requests (api_key, message, status, created, scheduled_time, sender_id, content_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (api_key, message, status, current_time, scheduled_time, sender_id, content_id))
        request_id = cursor.lastrowid
        
        # Add recipients
        for phone_number in phone_numbers:
            cursor.execute('''
                INSERT INTO sms_recipients (request_id, phone_number, status)
                VALUES (?, ?, ?)
            ''', (request_id, phone_number, 'Pending'))
        
        return request_id

def get_sms_request(request_id):
    """Get SMS request details."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM sms_requests WHERE request_id = ?', (request_id,))
        row = cursor.fetchone()
        if row:
            request_data = dict(row)
            # Get recipients
            cursor.execute('SELECT * FROM sms_recipients WHERE request_id = ?', (request_id,))
            recipients = [dict(r) for r in cursor.fetchall()]
            request_data['recipients'] = recipients
            request_data['phone_numbers'] = [r['phone_number'] for r in recipients]
            return request_data
    return None

def update_sms_request_status(request_id, status):
    """Update SMS request status."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE sms_requests 
            SET status = ? 
            WHERE request_id = ?
        ''', (status, request_id))

def update_recipient_status(request_id, phone_number, status):
    """Update recipient status."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE sms_recipients 
            SET status = ? 
            WHERE request_id = ? AND phone_number = ?
        ''', (status, request_id, phone_number))

# Statistics operations
def increment_stat(stat_name):
    """Increment a statistics counter."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE usage_stats 
            SET stat_value = stat_value + 1 
            WHERE stat_name = ?
        ''', (stat_name,))

def get_stat(stat_name):
    """Get a statistics value."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT stat_value FROM usage_stats WHERE stat_name = ?', (stat_name,))
        row = cursor.fetchone()
        if row:
            return row['stat_value']
    return 0

def get_all_stats():
    """Get all statistics."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT stat_name, stat_value FROM usage_stats')
        return {row['stat_name']: row['stat_value'] for row in cursor.fetchall()}

