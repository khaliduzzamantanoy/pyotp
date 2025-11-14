# OTP Server API Documentation

## Overview

This API provides endpoints for sending SMS messages (including OTP), checking delivery status, verifying OTP codes, and managing account balance. The API follows a structure similar to `api.sms.net.bd`.

**Base URL:** `http://your-server:5000`

**Authentication:** All endpoints require an API key passed as a query parameter or header.

---

## Table of Contents

1. [Send SMS](#1-send-sms)
2. [Check Delivery Report](#2-check-delivery-report)
3. [Check Balance](#3-check-balance)
4. [Verify OTP](#4-verify-otp)
5. [Device Pulling API](#5-device-pulling-api-optional)
6. [Error Codes](#error-codes)
7. [Phone Number Format](#phone-number-format)

---

## 1. Send SMS

Send SMS messages to one or more recipients. The message should include the OTP code if sending an OTP.

### Endpoint

```
GET/POST /api/sendsms
```

### Authentication

- **Query Parameter:** `api_key=YOUR_API_KEY`
- **Header (Alternative):** `X-API-Key: YOUR_API_KEY`

### Parameters

| Parameter    | Type   | Required | Description                                                                  |
| ------------ | ------ | -------- | ---------------------------------------------------------------------------- |
| `api_key`    | string | Yes      | Your API key for authentication                                              |
| `msg`        | string | Yes      | The message content. OTP should be included in the message                   |
| `to`         | string | Yes      | Recipient phone number(s). Multiple numbers separated by comma (,)           |
| `schedule`   | string | No       | Schedule date and time in format `Y-m-d H:i:s` (e.g., `2025-11-13 22:54:50`) |
| `sender_id`  | string | No       | Approved Sender ID (if available)                                            |
| `content_id` | string | No       | Approved campaign content ID (for bulk SMS)                                  |

### Request Examples

#### GET Request

```bash
curl "http://your-server:5000/api/sendsms?api_key=YOUR_API_KEY&msg=Your%20OTP%20is%20123456&to=8801800000000"
```

#### POST Request (JSON)

```bash
curl -X POST "http://your-server:5000/api/sendsms?api_key=YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "msg": "Your OTP is 123456",
    "to": "8801800000000"
  }'
```

#### Multiple Recipients

```bash
curl "http://your-server:5000/api/sendsms?api_key=YOUR_API_KEY&msg=Your%20OTP%20is%20123456&to=8801800000000,8801900000000"
```

#### Scheduled SMS

```bash
curl "http://your-server:5000/api/sendsms?api_key=YOUR_API_KEY&msg=Your%20OTP%20is%20123456&to=8801800000000&schedule=2025-11-13%2022:54:50"
```

### Response

#### Success Response

```json
{
  "error": 0,
  "msg": "Request successfully submitted",
  "data": {
    "request_id": 1
  }
}
```

#### Error Responses

```json
{
  "error": 1,
  "msg": "Invalid or missing API key"
}
```

```json
{
  "error": 1,
  "msg": "SMS balance exhausted"
}
```

```json
{
  "error": 1,
  "msg": "Message (msg) is required"
}
```

```json
{
  "error": 1,
  "msg": "Invalid phone number format: 123456"
}
```

### Notes

- The message (`msg`) parameter should contain the complete SMS text, including the OTP code
- Phone numbers can be in format `01XXXXXXXXX` or `8801XXXXXXXXX` (both are accepted)
- Multiple recipients are supported by separating phone numbers with commas
- Scheduled SMS will be sent at the specified time
- Each SMS sent deducts 1 from your SMS balance

---

## 2. Check Delivery Report

Check the delivery status of a previously sent SMS request.

### Endpoint

```
GET /api/report/request/{request_id}/
```

### Authentication

- **Query Parameter:** `api_key=YOUR_API_KEY`

### Parameters

| Parameter    | Type    | Required | Description                                                             |
| ------------ | ------- | -------- | ----------------------------------------------------------------------- |
| `request_id` | integer | Yes      | The request ID returned from the send SMS endpoint (URL path parameter) |
| `api_key`    | string  | Yes      | Your API key for authentication                                         |

### Request Example

```bash
curl "http://your-server:5000/api/report/request/1/?api_key=YOUR_API_KEY"
```

### Response

#### Success Response

```json
{
  "error": 0,
  "msg": "Success",
  "data": {
    "request_id": 1,
    "request_status": "Complete",
    "request_charge": "0.0000",
    "recipients": [
      {
        "number": "8801800000000",
        "charge": "0.0000",
        "status": "Sent"
      }
    ]
  }
}
```

#### Request Status Values

- `Pending` - Request is queued but not yet sent
- `Scheduled` - Request is scheduled for future delivery
- `Complete` - All recipients received the SMS successfully
- `Partial` - Some recipients failed to receive the SMS

#### Recipient Status Values

- `Pending` - SMS not yet sent
- `Sent` - SMS sent successfully
- `Failed` - SMS sending failed

#### Error Responses

```json
{
  "error": 1,
  "msg": "Invalid or missing API key"
}
```

```json
{
  "error": 1,
  "msg": "Request not found"
}
```

```json
{
  "error": 1,
  "msg": "Unauthorized access to this request"
}
```

---

## 3. Check Balance

Check your current SMS balance.

### Endpoint

```
GET /api/user/balance/
```

### Authentication

- **Query Parameter:** `api_key=YOUR_API_KEY`

### Parameters

| Parameter | Type   | Required | Description                     |
| --------- | ------ | -------- | ------------------------------- |
| `api_key` | string | Yes      | Your API key for authentication |

### Request Example

```bash
curl "http://your-server:5000/api/user/balance/?api_key=YOUR_API_KEY"
```

### Response

#### Success Response

```json
{
  "error": 0,
  "msg": "Success",
  "data": {
    "balance": "100.0000"
  }
```

#### Error Response

```json
{
  "error": 1,
  "msg": "Invalid or missing API key"
}
```

### Notes

- Balance is returned as a string with 4 decimal places
- Balance of `0.0000` means no SMS credits available
- Balance expires after 30 days (configurable by admin)

---

## 4. Verify OTP

Verify an OTP code that was sent to a phone number.

### Endpoint

```
POST /api/verify_otp
```

### Authentication

- **Header:** `X-API-Key: YOUR_API_KEY`
- **Content-Type:** `application/json`

### Parameters

| Parameter      | Type   | Required | Description                            |
| -------------- | ------ | -------- | -------------------------------------- |
| `phone_number` | string | Yes      | The phone number that received the OTP |
| `otp_code`     | string | Yes      | The OTP code to verify                 |

### Request Example

```bash
curl -X POST "http://your-server:5000/api/verify_otp" \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "phone_number": "8801800000000",
    "otp_code": "123456"
  }'
```

### Response

#### Success Response

```json
{
  "success": true,
  "message": "OTP verified successfully",
  "phone_number": "8801800000000"
}
```

#### Error Responses

```json
{
  "error": "Invalid or missing API key"
}
```

```json
{
  "error": "Invalid Bangladesh phone number format"
}
```

```json
{
  "error": "OTP code is required"
}
```

```json
{
  "error": "OTP expired"
}
```

```json
{
  "error": "Invalid OTP or phone number"
}
```

### Notes

- OTP codes expire after 2 minutes (120 seconds)
- Each OTP can only be used once
- Phone number can be in format `01XXXXXXXXX` or `8801XXXXXXXXX`

---

## 5. Device Pulling API (Optional)

This endpoint is for MicroPython devices to pull pending SMS send instructions from the queue.

### Endpoint

```
GET /get_pending_otp_send
```

### Authentication

None required (internal device endpoint)

### Request Example

```bash
curl "http://your-server:5000/get_pending_otp_send"
```

### Response

#### Pending SMS Available

```json
{
  "send_otp": true,
  "target_phone_number": "8801800000000",
  "message": "Your OTP code is 123456. Valid for 2 minutes.",
  "otp_code": "123456"
}
```

#### No Pending SMS

```json
{
  "send_otp": false
}
```

### Notes

- This endpoint is designed for MicroPython devices
- Devices should poll this endpoint periodically
- Each call returns one pending SMS instruction
- Continue polling until `send_otp` is `false`

---

## Error Codes

| HTTP Status | Error Code | Description                                 |
| ----------- | ---------- | ------------------------------------------- |
| 200         | 0          | Success                                     |
| 400         | 1          | Bad Request (invalid parameters)            |
| 401         | 1          | Unauthorized (invalid or missing API key)   |
| 402         | 1          | Payment Required (insufficient SMS balance) |
| 403         | 1          | Forbidden (unauthorized access)             |
| 404         | 1          | Not Found (request ID not found)            |
| 500         | 1          | Internal Server Error                       |

### Error Response Format

All error responses follow this format:

```json
{
  "error": 1,
  "msg": "Error message description"
}
```

---

## Phone Number Format

### Accepted Formats

1. **Local Format:** `01XXXXXXXXX` (11 digits, starts with 01)

   - Example: `01712345678`

2. **International Format:** `8801XXXXXXXXX` (13 digits, starts with 880)
   - Example: `8801712345678`

### Validation Rules

- Must start with `01` (local) or `880` (international)
- Third digit must be between 3-9
- Total length: 11 digits (local) or 13 digits (international)
- The server automatically normalizes to international format (`880`) for storage

### Examples

| Input           | Normalized      |
| --------------- | --------------- |
| `01712345678`   | `8801712345678` |
| `8801712345678` | `8801712345678` |
| `01987654321`   | `8801987654321` |

---

## Complete Workflow Example

### Step 1: Send OTP SMS

```bash
curl "http://your-server:5000/api/sendsms?api_key=YOUR_API_KEY&msg=Your%20OTP%20is%20123456&to=8801800000000"
```

**Response:**

```json
{
  "error": 0,
  "msg": "Request successfully submitted",
  "data": {
    "request_id": 1
  }
}
```

### Step 2: Check Delivery Status

```bash
curl "http://your-server:5000/api/report/request/1/?api_key=YOUR_API_KEY"
```

**Response:**

```json
{
  "error": 0,
  "msg": "Success",
  "data": {
    "request_id": 1,
    "request_status": "Complete",
    "request_charge": "0.0000",
    "recipients": [
      {
        "number": "8801800000000",
        "charge": "0.0000",
        "status": "Sent"
      }
    ]
  }
}
```

### Step 3: Verify OTP

```bash
curl -X POST "http://your-server:5000/api/verify_otp" \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "phone_number": "8801800000000",
    "otp_code": "123456"
  }'
```

**Response:**

```json
{
  "success": true,
  "message": "OTP verified successfully",
  "phone_number": "8801800000000"
}
```

---

## Rate Limiting

Currently, there are no rate limits enforced. However, please use the API responsibly.

---

## Support

For API key management, balance top-up, and account issues, please contact your administrator or access the admin dashboard at `/admin`.

---

## Changelog

### Version 1.0

- Initial API release
- Send SMS endpoint
- Delivery report endpoint
- Balance check endpoint
- OTP verification endpoint
- Device pulling API

---

**Last Updated:** 2025-01-XX
