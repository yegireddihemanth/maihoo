# Verification Consent API Schemas

## 📋 **Complete API Documentation**

### **Base URL:** `http://localhost:8000`

---

## 🔐 **1. Send Verification Consent Email**

### **Endpoint:**
```http
POST /secure/verification/{candidateId}/send-consent
Authorization: Bearer <token>
Content-Type: application/json
```

### **Path Parameters:**
- `candidateId` (string, required): MongoDB ObjectId of the candidate

### **Request Schema:**
```json
{
  "verificationChecks": [
    {
      "name": "Employment Verification",
      "description": "Verify employment history, job titles, and employment dates"
    },
    {
      "name": "Education Verification", 
      "description": "Verify educational qualifications, degrees, and institutions"
    },
    {
      "name": "Criminal Background Check",
      "description": "Check for any criminal records or legal issues"
    }
  ]
}
```

**Or send empty request for default checks:**
```json
{}
```

### **Field Validation:**
- `verificationChecks` (array, optional): List of verification checks to be performed
  - `name` (string, required): Max 100 characters  
  - `description` (string, optional): Max 500 characters

**Note**: 
- The consent URL is configured in the backend code and doesn't need to be passed in the request.
- If `verificationChecks` is not provided or empty, default verification checks will be used automatically.

### **Success Response (200):**
```json
{
  "message": "Verification consent email sent successfully",
  "candidateId": "507f1f77bcf86cd799439011",
  "candidateEmail": "john.doe@example.com",
  "candidateName": "John Doe",
  "organizationName": "Acme Corp",
  "consentToken": "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
  "expiresAt": "2025-12-02T06:43:44.168521+00:00",
  "checksRequested": 5,
  "emailSent": true
}
```

### **Error Responses:**

#### **400 Bad Request - Invalid Candidate ID:**
```json
{
  "detail": "Invalid candidate ID"
}
```

#### **400 Bad Request - Missing Verification Checks:**
```json
{
  "detail": "Verification checks list is required"
}
```

#### **403 Forbidden - Not Authorized:**
```json
{
  "detail": "Not authorized to send consent emails"
}
```

#### **403 Forbidden - No Organization Access:**
```json
{
  "detail": "Not authorized to access this candidate"
}
```

#### **404 Not Found - Candidate Not Found:**
```json
{
  "detail": "Candidate not found"
}
```

#### **409 Conflict - Consent Already Given:**
```json
{
  "message": "Consent already provided by candidate",
  "consentStatus": "ALREADY_GIVEN",
  "consentDate": "2025-11-30T08:15:00.000Z",
  "candidateEmail": "john.doe@example.com"
}
```

#### **500 Internal Server Error - Email Failed:**
```json
{
  "detail": "Failed to send consent email: GMAIL API ERROR: ..."
}
```

### **Authorization Roles:**
- `SUPER_ADMIN` - Can send for any candidate
- `SUPER_SPOC` - Can send for any candidate  
- `SUPER_ADMIN_HELPER` - Can send for candidates in accessible organizations
- `ORG_HR` - Can send for candidates in their organization
- `SPOC` - Can send for candidates in their organization

---

## 🌐 **2. Get Consent Details (Public)**

### **Endpoint:**
```http
GET /public/verification-consent/{token}
```

### **Path Parameters:**
- `token` (string, required): Consent token from email link

### **Success Response (200) - Pending Consent:**
```json
{
  "candidateId": "507f1f77bcf86cd799439011",
  "candidateName": "John Doe",
  "candidateEmail": "john.doe@example.com",
  "organizationName": "Acme Corp",
  "organizationId": "507f1f77bcf86cd799439012",
  "verificationChecks": [
    {
      "name": "Employment Verification",
      "description": "Verify employment history, job titles, and employment dates"
    },
    {
      "name": "Education Verification",
      "description": "Verify educational qualifications, degrees, and institutions"
    },
    {
      "name": "Criminal Background Check", 
      "description": "Check for any criminal records or legal issues"
    }
  ],
  "consentRequestedAt": "2025-11-30T06:43:44.168521+00:00",
  "consentRequestedBy": "hr@acme.com",
  "tokenExpiresAt": "2025-12-02T06:43:44.168521+00:00",
  "status": "PENDING_CONSENT",
  "timeRemaining": "47 hours 23 minutes"
}
```

### **Success Response (200) - Already Consented:**
```json
{
  "status": "ALREADY_CONSENTED",
  "message": "Consent has already been provided for this verification",
  "consentDate": "2025-11-30T08:15:00.000Z",
  "candidateName": "John Doe",
  "organizationName": "Acme Corp"
}
```

### **Error Responses:**

#### **404 Not Found - Invalid/Expired Token:**
```json
{
  "detail": "Invalid or expired consent token"
}
```

---

## ✅ **3. Submit Consent (Public)**

### **Endpoint:**
```http
POST /public/verification-consent/{token}/submit
Content-Type: application/json
```

### **Path Parameters:**
- `token` (string, required): Consent token from email link

### **Request Schema:**
```json
{
  "consentGiven": true
}
```

### **Field Validation:**
- `consentGiven` (boolean, required): Must be `true` or `false`

**Note**: Only the consent decision is required. All other fields are automatically captured by the system.

### **Success Response (200) - Consent Given:**
```json
{
  "status": "CONSENT_GIVEN",
  "message": "Thank you! Your consent has been recorded. Verification process can now begin.",
  "consentDate": "2025-11-30T08:15:00.000Z",
  "candidateName": "John Doe",
  "candidateEmail": "john.doe@example.com",
  "organizationName": "Acme Corp",
  "checksConsented": 3,
  "nextSteps": "The organization will now proceed with the verification process. You may be contacted for additional information if needed."
}
```

### **Success Response (200) - Consent Denied:**
```json
{
  "status": "CONSENT_DENIED",
  "message": "Your response has been recorded. Verification process will not proceed without consent.",
  "consentDate": "2025-11-30T08:15:00.000Z",
  "candidateName": "John Doe",
  "candidateEmail": "john.doe@example.com",
  "organizationName": "Acme Corp",
  "nextSteps": "The organization has been notified of your decision. No verification checks will be performed."
}
```

### **Error Responses:**

#### **400 Bad Request - Missing Consent Field:**
```json
{
  "detail": "consentGiven field is required (true/false)"
}
```

#### **404 Not Found - Invalid/Expired Token:**
```json
{
  "detail": "Invalid or expired consent token"
}
```

#### **409 Conflict - Already Submitted:**
```json
{
  "status": "ALREADY_CONSENTED",
  "message": "Consent has already been provided for this verification",
  "consentDate": "2025-11-30T08:15:00.000Z"
}
```

---

## 📊 **4. Check Consent Status (Internal)**

### **Endpoint:**
```http
GET /secure/verification/{candidateId}/consent-status
Authorization: Bearer <token>
```

### **Path Parameters:**
- `candidateId` (string, required): MongoDB ObjectId of the candidate

### **Success Response (200):**
```json
{
  "candidateId": "507f1f77bcf86cd799439011",
  "candidateName": "John Doe",
  "candidateEmail": "john.doe@example.com",
  "organizationName": "Acme Corp",
  "consentStatus": "CONSENT_GIVEN",
  "consentRequested": true,
  "consentRequestedAt": "2025-11-30T06:43:44.168521+00:00",
  "consentRequestedBy": "hr@acme.com",
  "consentAcknowledged": true,
  "consentDate": "2025-11-30T08:15:00.000Z",
  "consentSubmittedAt": "2025-11-30T08:15:00.000Z",
  "verificationChecksRequested": [
    {
      "name": "Employment Verification",
      "description": "Verify employment history, job titles, and employment dates"
    },
    {
      "name": "Education Verification",
      "description": "Verify educational qualifications, degrees, and institutions"
    }
  ],
  "canStartVerification": true,
  "tokenExpired": false,
  "daysUntilExpiry": null
}
```

### **Consent Status Values:**
- `NOT_REQUESTED` - No consent request sent yet
- `PENDING_CONSENT` - Consent requested, waiting for candidate response
- `CONSENT_GIVEN` - Candidate provided consent (verification can proceed)
- `CONSENT_DENIED` - Candidate denied consent (verification blocked)
- `TOKEN_EXPIRED` - Consent token expired without response

### **Error Responses:**

#### **400 Bad Request - Invalid Candidate ID:**
```json
{
  "detail": "Invalid candidate ID"
}
```

#### **403 Forbidden - Not Authorized:**
```json
{
  "detail": "Not authorized"
}
```

#### **403 Forbidden - No Organization Access:**
```json
{
  "detail": "Not authorized to access this candidate"
}
```

#### **404 Not Found - Candidate Not Found:**
```json
{
  "detail": "Candidate not found"
}
```

---

## 🧪 **Complete Testing Examples**

### **Test Scenario 1: Complete Consent Flow**

#### **Step 1: Send Consent Request**
```bash
curl -X POST "http://localhost:8000/secure/verification/507f1f77bcf86cd799439011/send-consent" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "verificationChecks": [
      {
        "name": "Employment Verification",
        "description": "Verify employment history and job titles"
      },
      {
        "name": "Education Verification",
        "description": "Verify educational qualifications and degrees"
      },
      {
        "name": "Criminal Background Check",
        "description": "Check for any criminal records"
      }
    ]
  }'
```

**Expected Response:**
```json
{
  "message": "Verification consent email sent successfully",
  "candidateId": "507f1f77bcf86cd799439011",
  "candidateEmail": "john.doe@example.com",
  "consentToken": "abc123def456...",
  "expiresAt": "2025-12-02T06:43:44.168521+00:00",
  "checksRequested": 3
}
```

#### **Step 2: Get Consent Details (Public)**
```bash
curl -X GET "http://localhost:8000/public/verification-consent/abc123def456..."
```

**Expected Response:**
```json
{
  "candidateName": "John Doe",
  "organizationName": "Acme Corp",
  "verificationChecks": [...],
  "status": "PENDING_CONSENT"
}
```

#### **Step 3: Submit Consent**
```bash
curl -X POST "http://localhost:8000/public/verification-consent/abc123def456.../submit" \
  -H "Content-Type: application/json" \
  -d '{
    "consentGiven": true
  }'
```

**Expected Response:**
```json
{
  "status": "CONSENT_GIVEN",
  "message": "Thank you! Your consent has been recorded.",
  "consentDate": "2025-11-30T08:15:00.000Z",
  "candidateName": "John Doe"
}
```

#### **Step 4: Check Consent Status**
```bash
curl -X GET "http://localhost:8000/secure/verification/507f1f77bcf86cd799439011/consent-status" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Expected Response:**
```json
{
  "candidateId": "507f1f77bcf86cd799439011",
  "consentStatus": "CONSENT_GIVEN",
  "canStartVerification": true,
  "consentDate": "2025-11-30T08:15:00.000Z"
}
```

---

### **Test Scenario 2: Error Cases**

#### **Invalid Candidate ID:**
```bash
curl -X POST "http://localhost:8000/secure/verification/invalid-id/send-consent" \
  -H "Authorization: Bearer ..." \
  -H "Content-Type: application/json" \
  -d '{"verificationChecks": [...]}'
```
**Expected:** `400 Bad Request - Invalid candidate ID`

#### **Expired Token:**
```bash
curl -X GET "http://localhost:8000/public/verification-consent/expired-token"
```
**Expected:** `404 Not Found - Invalid or expired consent token`

#### **Already Consented:**
```bash
curl -X POST "http://localhost:8000/public/verification-consent/used-token/submit" \
  -H "Content-Type: application/json" \
  -d '{"consentGiven": true}'
```
**Expected:** `409 Conflict - Already consented`

#### **Missing Authorization:**
```bash
curl -X POST "http://localhost:8000/secure/verification/507f1f77bcf86cd799439011/send-consent" \
  -H "Content-Type: application/json" \
  -d '{"verificationChecks": [...]}'
```
**Expected:** `401 Unauthorized`

#### **Consent Denied:**
```bash
curl -X POST "http://localhost:8000/public/verification-consent/valid-token/submit" \
  -H "Content-Type: application/json" \
  -d '{"consentGiven": false}'
```
**Expected:** `200 OK - CONSENT_DENIED status`

---

## 📧 **Email Content Example**

When consent email is sent, candidate receives:

```
Subject: Verification Consent Required - Acme Corp

Dear John Doe,

Acme Corp has requested to perform background verification checks on your profile.

Before we begin the verification process, we need your explicit consent to proceed with the following checks:

VERIFICATION CHECKS TO BE PERFORMED:
1. Employment Verification
   - Verify employment history, job titles, and employment dates
2. Education Verification
   - Verify educational qualifications, degrees, and institutions
3. Criminal Background Check
   - Check for any criminal records or legal issues

IMPORTANT INFORMATION:
- These checks will be conducted by our verification team
- Your personal information will be handled securely and confidentially
- You have the right to know what checks are being performed
- This consent is required before any verification can begin

WHAT YOU NEED TO DO:
1. Click the consent link below
2. Review the detailed list of verification checks
3. Provide your consent by checking the agreement box
4. Submit your response

CONSENT LINK: https://your-frontend.com/consent?token=abc123def456...

This consent link will expire on: 2025-12-02 06:43:44 UTC

If you have any questions about these verification checks or need clarification, please contact:
- Organization: Acme Corp
- Support: support@bgvapp.in

If you did not expect this verification request, please contact us immediately.

Thank you for your cooperation.

Best regards,
BGVApp Verification Team
```

---

## 🗄️ **Database Schema**

### **Candidate Collection Updates:**
```javascript
{
  // Existing candidate fields...
  "_id": ObjectId("507f1f77bcf86cd799439011"),
  "candidateName": "John Doe",
  "email": "john.doe@example.com",
  "organizationId": "507f1f77bcf86cd799439012",
  "organizationName": "Acme Corp",
  
  // New consent fields
  "consentRequested": true,
  "consentRequestedAt": "2025-11-30T06:43:44.168521+00:00",
  "consentRequestedBy": "hr@acme.com",
  "consentToken": "abc123def456...",  // Cleared after submission
  "consentTokenExpiry": "2025-12-02T06:43:44.168521+00:00",
  "consentAcknowledged": true,  // true/false/null
  "consentDate": "2025-11-30T08:15:00.000Z",
  "consentSubmittedAt": "2025-11-30T08:15:00.000Z",
  "verificationChecksRequested": [
    {
      "name": "Employment Verification",
      "description": "Verify employment history, job titles, and employment dates"
    },
    {
      "name": "Education Verification",
      "description": "Verify educational qualifications, degrees, and institutions"
    }
  ]
}
```

---

## 🔒 **Security Considerations**

### **Token Security:**
- **Length:** 43 characters (32 bytes base64url encoded)
- **Entropy:** 256 bits of randomness
- **Expiry:** 48 hours maximum
- **Single Use:** Token cleared after submission
- **No Reuse:** New token required for each consent request

### **Rate Limiting Recommendations:**
- **Send Consent:** 5 requests per candidate per hour
- **Get Consent Details:** 100 requests per token per hour
- **Submit Consent:** 3 attempts per token total

### **Audit Trail:**
- All consent actions logged with timestamps
- IP address and user agent captured
- Digital signature support
- Activity logging for compliance

This comprehensive API documentation provides everything needed to implement the verification consent system! 🎉