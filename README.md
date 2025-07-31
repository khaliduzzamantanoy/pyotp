# OTP Server API Documentation

## Overview

This OTP (One-Time Password) server provides API endpoints for generating and verifying OTP codes for Bangladesh phone numbers. The server is designed to work with external user servers that generate OTP codes and send them via SMS using a MicroPython device.

## Features

- **API-based OTP Generation**: External servers can generate OTPs via API
- **OTP Verification**: Verify OTP codes via API
- **MicroPython Device Integration**: Queue system for SMS sending
- **Admin Dashboard**: Monitor usage and manage API keys
- **API Key Authentication**: Secure access control
- **Usage Statistics**: Track API usage and success rates

## Server Setup

### Prerequisites

```bash
pip install flask
```

### Running the Server

```bash
python server.py
```

The server will start on `http://0.0.0.0:5000`

## API Endpoints

### 1. Generate OTP

**Endpoint:** `POST /api/generate_otp`

**Headers Required:**

```
X-API-Key: your_api_key
Content-Type: application/json
```

**Request Body:**

```json
{
  "phone_number": "01712345678",
  "otp_code": "123456"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "OTP 123456 generated for 01712345678",
  "phone_number": "01712345678",
  "otp_code": "123456",
  "expires_in": 120
}
```

**Response (Error):**

```json
{
  "error": "Invalid Bangladesh phone number format"
}
```

### 2. Verify OTP

**Endpoint:** `POST /api/verify_otp`

**Headers Required:**

```
X-API-Key: your_api_key
Content-Type: application/json
```

**Request Body:**

```json
{
  "phone_number": "01712345678",
  "otp_code": "123456"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "OTP verified successfully",
  "phone_number": "01712345678"
}
```

**Response (Error):**

```json
{
  "error": "Invalid OTP or phone number"
}
```

### 3. Get Pending OTP for Device

**Endpoint:** `GET /get_pending_otp_send`

**Response (Pending OTP):**

```json
{
  "send_otp": true,
  "target_phone_number": "01712345678",
  "otp_code": "123456"
}
```

**Response (No Pending OTP):**

```json
{
  "send_otp": false
}
```

## Admin Dashboard

### Access

Visit `http://your-server:5000/admin` and login with the admin password.

**Default Password:** `admin123` (Change this in production)

### Features

1. **Usage Statistics**

   - Total OTP requests
   - Total OTP verifications
   - Successful verifications
   - Failed verifications

2. **API Key Management**

   - View existing API keys
   - Create new API keys
   - Track usage per API key

3. **Documentation**
   - Built-in API documentation
   - Request/response examples

## API Key Management

### Creating API Keys

1. Access the admin dashboard at `/admin`
2. Login with admin password
3. Enter a username for the new API key
4. Click "Create API Key"
5. Save the generated API key securely

### Using API Keys

Include the API key in the `X-API-Key` header for all API requests:

```bash
curl -X POST http://your-server:5000/api/generate_otp \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{"phone_number": "01712345678", "otp_code": "123456"}'
```

## Phone Number Validation

The server validates Bangladesh phone numbers using the following format:

- Must start with `01`
- Followed by digits 3-9
- Total length: 11 digits
- Example: `01712345678`

## OTP Expiry

- OTP codes expire after 2 minutes (120 seconds)
- Expired OTPs cannot be verified
- Each OTP can only be used once

## Error Codes

| Status Code | Description                    |
| ----------- | ------------------------------ |
| 200         | Success                        |
| 400         | Bad Request (invalid data)     |
| 401         | Unauthorized (invalid API key) |
| 404         | Not Found                      |

## MicroPython Device Integration

The server maintains a queue of pending OTP sends that your MicroPython device can poll:

1. Device polls `/get_pending_otp_send`
2. If `send_otp` is `true`, send SMS to `target_phone_number` with `otp_code`
3. Continue polling for more pending sends

## Security Considerations

1. **Change Default Password**: Modify `ADMIN_PASSWORD` in the code
2. **Use HTTPS**: In production, use HTTPS for all API calls
3. **Environment Variables**: Store sensitive data in environment variables
4. **Rate Limiting**: Consider implementing rate limiting for production use
5. **API Key Rotation**: Regularly rotate API keys

## Example Usage

### Python Client Example

```python
import requests

# API configuration
API_BASE_URL = "http://your-server:5000"
API_KEY = "your_api_key"

headers = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json"
}

# Generate OTP
def generate_otp(phone_number, otp_code):
    data = {
        "phone_number": phone_number,
        "otp_code": otp_code
    }
    response = requests.post(f"{API_BASE_URL}/api/generate_otp",
                           headers=headers, json=data)
    return response.json()

# Verify OTP
def verify_otp(phone_number, otp_code):
    data = {
        "phone_number": phone_number,
        "otp_code": otp_code
    }
    response = requests.post(f"{API_BASE_URL}/api/verify_otp",
                           headers=headers, json=data)
    return response.json()

# Usage
result = generate_otp("01712345678", "123456")
print(result)
```

### cURL Examples

**Generate OTP:**

```bash
curl -X POST http://your-server:5000/api/generate_otp \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{"phone_number": "01712345678", "otp_code": "123456"}'
```

**Verify OTP:**

```bash
curl -X POST http://your-server:5000/api/verify_otp \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{"phone_number": "01712345678", "otp_code": "123456"}'
```

**Get Pending OTP:**

```bash
curl -X GET http://your-server:5000/get_pending_otp_send
```

## Troubleshooting

### Common Issues

1. **401 Unauthorized**: Check your API key
2. **400 Bad Request**: Verify phone number format and OTP code
3. **404 Not Found**: Ensure you're using the correct endpoint URL

### Debug Mode

The server runs in debug mode by default. Check the console output for detailed error messages.

## Production Deployment

1. Set `debug=False` in the server configuration
2. Use a production WSGI server (e.g., Gunicorn)
3. Configure HTTPS
4. Set up proper logging
5. Use environment variables for sensitive data
6. Implement rate limiting
7. Set up monitoring and alerting
