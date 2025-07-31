#!/usr/bin/env python3
"""
Test script for OTP Server API
This script demonstrates how to use the API endpoints
"""

import requests
import json
import time

# Configuration
SERVER_URL = "http://localhost:5000"
API_KEY = "your_api_key_here"  # Replace with your actual API key

# Headers for API requests
headers = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json"
}

def test_generate_otp():
    """Test OTP generation"""
    print("=== Testing OTP Generation ===")
    
    data = {
        "phone_number": "01712345678",
        "otp_code": "123456"
    }
    
    try:
        response = requests.post(f"{SERVER_URL}/api/generate_otp", 
                               headers=headers, json=data)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

def test_verify_otp(phone_number, otp_code):
    """Test OTP verification"""
    print(f"\n=== Testing OTP Verification ===")
    
    data = {
        "phone_number": phone_number,
        "otp_code": otp_code
    }
    
    try:
        response = requests.post(f"{SERVER_URL}/api/verify_otp", 
                               headers=headers, json=data)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

def test_get_pending_otp():
    """Test getting pending OTP for device"""
    print(f"\n=== Testing Get Pending OTP ===")
    
    try:
        response = requests.get(f"{SERVER_URL}/get_pending_otp_send")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

def test_invalid_api_key():
    """Test with invalid API key"""
    print(f"\n=== Testing Invalid API Key ===")
    
    invalid_headers = {
        "X-API-Key": "invalid_key",
        "Content-Type": "application/json"
    }
    
    data = {
        "phone_number": "01712345678",
        "otp_code": "123456"
    }
    
    try:
        response = requests.post(f"{SERVER_URL}/api/generate_otp", 
                               headers=invalid_headers, json=data)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def test_invalid_phone():
    """Test with invalid phone number"""
    print(f"\n=== Testing Invalid Phone Number ===")
    
    data = {
        "phone_number": "1234567890",  # Invalid format
        "otp_code": "123456"
    }
    
    try:
        response = requests.post(f"{SERVER_URL}/api/generate_otp", 
                               headers=headers, json=data)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def test_insufficient_balance():
    """Test with insufficient SMS balance"""
    print(f"\n=== Testing Insufficient Balance ===")
    
    # This test requires an API key with 0 balance
    # You'll need to create one via admin dashboard first
    data = {
        "phone_number": "01712345678",
        "otp_code": "123456"
    }
    
    try:
        response = requests.post(f"{SERVER_URL}/api/generate_otp", 
                               headers=headers, json=data)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def main():
    """Run all tests"""
    print("OTP Server API Test Script")
    print("=" * 50)
    
    # Check if server is running
    try:
        response = requests.get(f"{SERVER_URL}/admin")
        print("✓ Server is running")
    except requests.exceptions.RequestException:
        print("✗ Server is not running. Please start the server first.")
        print("Run: python server.py")
        return
    
    # Test 1: Generate OTP
    result = test_generate_otp()
    if result and result.get("success"):
        phone_number = result.get("phone_number")
        otp_code = result.get("otp_code")
        
        # Test 2: Verify OTP (should succeed)
        test_verify_otp(phone_number, otp_code)
        
        # Test 3: Verify OTP again (should fail - already used)
        test_verify_otp(phone_number, otp_code)
        
        # Test 4: Verify with wrong OTP
        test_verify_otp(phone_number, "999999")
    
    # Test 5: Get pending OTP
    test_get_pending_otp()
    
    # Test 6: Invalid API key
    test_invalid_api_key()
    
    # Test 7: Invalid phone number
    test_invalid_phone()
    
    # Test 8: Insufficient balance
    test_insufficient_balance()
    
    print("\n" + "=" * 50)
    print("Test completed!")

if __name__ == "__main__":
    main() 