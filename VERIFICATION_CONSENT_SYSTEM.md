# Verification Consent System

## 🎯 **Overview**

The Verification Consent System ensures that candidates provide explicit consent before any backend verification checks are performed. This system implements a secure, token-based consent mechanism with email notifications.

## 🔄 **Consent Workflow**

```
1. HR/Admin initiates verification
   ↓
2. System sends consent email to candidate
   ↓
3. Candidate clicks consent link
   ↓
4. Candidate reviews verification checks
   ↓
5. Candidate provides consent (Yes/No)
   ↓
6. System updates candidate record
   ↓
7. Verification can proceed (if consent given)
```

---

## 📋 **API Endpoints**

### **1. Send Verification Consent Email**

```http
POST /secure/verification/{candidateId}/send-consent
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Schema:**
```json
{
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
      "description": "Check for any criminal records or legal issues"
    }
  ],
  "consentUrl": "https://your-frontend.com/consent"  // Optional
}
```

**Response Schema:**
```json
{
  "message": "Verification consent email sent successfully",
  "candidateId": "507f1f77bcf86cd799439011",
  "candidateEmail": "candidate@example.com",
  "consentToken": "abc123def456...",
  "expiresAt": "2025-12-02T06:43:44.168521+00:00",
  "checksRequested": 3
}
```

**Authorization:**
- `SUPER_ADMIN`, `SUPER_SPOC` - Can send for any candidate
- `SUPER_ADMIN_HELPER` - Can send for candidates in accessible organizations
- `ORG_HR`, `SPOC` - Can send for candidates in their organization

---

### **2. Get Consent Details (Public)**

```http
GET /public/verification-consent/{token}
```

**Response Schema:**
```json
{
  "candidateId": "507f1f77bcf86cd799439011",
  "candidateName": "John Doe",
  "candidateEmail": "john.doe@example.com",
  "organizationName": "Acme Corp",
  "verificationChecks": [
    {
      "name": "Employment Verification",
      "description": "Verify employment history and job titles"
    },
    {
      "name": "Education Verification",
      "description": "Verify educational qualifications and degrees"
    }
  ],
  "consentRequestedAt": "2025-11-30T06:43:44.168521+00:00",
  "consentRequestedBy": "hr@acme.com",
  "tokenExpiresAt": "2025-12-02T06:43:44.168521+00:00",
  "status": "PENDING_CONSENT"
}
```

**Error Responses:**
```json
// Token expired or invalid
{
  "detail": "Invalid or expired consent token"
}

// Already consented
{
  "status": "ALREADY_CONSENTED",
  "message": "Consent has already been provided for this verification",
  "consentDate": "2025-11-30T08:15:00.000Z"
}
```

---

### **3. Submit Consent (Public)**

```http
POST /public/verification-consent/{token}/submit
Content-Type: application/json
```

**Request Schema:**
```json
{
  "consentGiven": true,                    // Required: true/false
  "candidateSignature": "John Doe",       // Optional: candidate's digital signature
  "ipAddress": "192.168.1.1",            // Optional: for audit trail
  "userAgent": "Mozilla/5.0..."           // Optional: for audit trail
}
```

**Response Schema (Consent Given):**
```json
{
  "status": "CONSENT_GIVEN",
  "message": "Thank you! Your consent has been recorded. Verification process can now begin.",
  "consentDate": "2025-11-30T08:15:00.000Z",
  "candidateName": "John Doe"
}
```

**Response Schema (Consent Denied):**
```json
{
  "status": "CONSENT_DENIED",
  "message": "Your response has been recorded. Verification process will not proceed without consent.",
  "consentDate": "2025-11-30T08:15:00.000Z", 
  "candidateName": "John Doe"
}
```

---

### **4. Check Consent Status (Internal)**

```http
GET /secure/verification/{candidateId}/consent-status
Authorization: Bearer <token>
```

**Response Schema:**
```json
{
  "candidateId": "507f1f77bcf86cd799439011",
  "candidateName": "John Doe",
  "candidateEmail": "john.doe@example.com",
  "consentStatus": "CONSENT_GIVEN",
  "consentRequested": true,
  "consentRequestedAt": "2025-11-30T06:43:44.168521+00:00",
  "consentRequestedBy": "hr@acme.com",
  "consentAcknowledged": true,
  "consentDate": "2025-11-30T08:15:00.000Z",
  "consentSignature": "John Doe",
  "verificationChecksRequested": [
    {
      "name": "Employment Verification",
      "description": "Verify employment history and job titles"
    }
  ],
  "canStartVerification": true
}
```

**Consent Status Values:**
- `NOT_REQUESTED` - No consent request sent yet
- `PENDING_CONSENT` - Consent requested, waiting for response
- `CONSENT_GIVEN` - Candidate gave consent
- `CONSENT_DENIED` - Candidate denied consent
- `TOKEN_EXPIRED` - Consent token expired without response

---

## 📧 **Email Template**

The consent email includes:

```
Subject: Verification Consent Required - [Organization Name]

Dear [Candidate Name],

[Organization Name] has requested to perform background verification checks on your profile.

Before we begin the verification process, we need your explicit consent to proceed with the following checks:

VERIFICATION CHECKS TO BE PERFORMED:
1. Employment Verification
   - Verify employment history and job titles
2. Education Verification
   - Verify educational qualifications and degrees
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

CONSENT LINK: [Consent URL with Token]

This consent link will expire on: [Expiry Date]

If you have any questions about these verification checks or need clarification, please contact:
- Organization: [Organization Name]
- Support: support@bgvapp.in

Thank you for your cooperation.

Best regards,
BGVApp Verification Team
```

---

## 🗄️ **Database Schema Updates**

### **Candidate Collection Fields Added:**

```javascript
{
  // Existing fields...
  
  // Consent-related fields
  "consentRequested": true,
  "consentRequestedAt": "2025-11-30T06:43:44.168521+00:00",
  "consentRequestedBy": "hr@acme.com",
  "consentToken": "abc123def456...",
  "consentTokenExpiry": "2025-12-02T06:43:44.168521+00:00",
  "consentAcknowledged": true,  // true/false/null
  "consentDate": "2025-11-30T08:15:00.000Z",
  "consentSubmittedAt": "2025-11-30T08:15:00.000Z",
  "consentSignature": "John Doe",
  "consentIpAddress": "192.168.1.1",
  "consentUserAgent": "Mozilla/5.0...",
  "verificationChecksRequested": [
    {
      "name": "Employment Verification",
      "description": "Verify employment history and job titles"
    }
  ]
}
```

---

## 🎨 **Frontend Integration**

### **1. Send Consent (Admin Interface)**

```javascript
const sendVerificationConsent = async (candidateId, checks) => {
  const response = await fetch(`/secure/verification/${candidateId}/send-consent`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      verificationChecks: checks,
      consentUrl: 'https://your-frontend.com/consent'
    })
  });
  
  const result = await response.json();
  
  if (response.ok) {
    showNotification(`Consent email sent to ${result.candidateEmail}`);
  } else {
    showError(result.detail);
  }
};

// Example usage
const verificationChecks = [
  {
    name: "Employment Verification",
    description: "Verify employment history and job titles"
  },
  {
    name: "Education Verification", 
    description: "Verify educational qualifications and degrees"
  }
];

sendVerificationConsent('507f1f77bcf86cd799439011', verificationChecks);
```

### **2. Consent Page (Public)**

```javascript
// Get consent details from URL token
const urlParams = new URLSearchParams(window.location.search);
const token = urlParams.get('token');

const loadConsentDetails = async () => {
  try {
    const response = await fetch(`/public/verification-consent/${token}`);
    const data = await response.json();
    
    if (response.ok) {
      if (data.status === 'ALREADY_CONSENTED') {
        showAlreadyConsentedMessage(data);
      } else {
        renderConsentForm(data);
      }
    } else {
      showError(data.detail);
    }
  } catch (error) {
    showError('Failed to load consent details');
  }
};

const renderConsentForm = (consentData) => {
  const checksHtml = consentData.verificationChecks.map(check => `
    <div class="verification-check">
      <h4>${check.name}</h4>
      <p>${check.description}</p>
    </div>
  `).join('');
  
  document.getElementById('consentForm').innerHTML = `
    <h2>Verification Consent Request</h2>
    <p><strong>Organization:</strong> ${consentData.organizationName}</p>
    <p><strong>Candidate:</strong> ${consentData.candidateName}</p>
    
    <h3>Verification Checks to be Performed:</h3>
    ${checksHtml}
    
    <div class="consent-agreement">
      <label>
        <input type="checkbox" id="consentCheckbox" required>
        I understand and consent to the verification checks listed above.
        I acknowledge that my personal information will be handled securely.
      </label>
    </div>
    
    <div class="signature-section">
      <label for="signature">Digital Signature (Optional):</label>
      <input type="text" id="signature" placeholder="Type your full name">
    </div>
    
    <div class="form-actions">
      <button onclick="submitConsent(true)" id="consentButton" disabled>
        Give Consent
      </button>
      <button onclick="submitConsent(false)" class="btn-secondary">
        Deny Consent
      </button>
    </div>
  `;
  
  // Enable consent button only when checkbox is checked
  document.getElementById('consentCheckbox').addEventListener('change', (e) => {
    document.getElementById('consentButton').disabled = !e.target.checked;
  });
};

const submitConsent = async (consentGiven) => {
  const signature = document.getElementById('signature').value;
  
  try {
    const response = await fetch(`/public/verification-consent/${token}/submit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        consentGiven: consentGiven,
        candidateSignature: signature || null,
        ipAddress: await getUserIP(), // Optional: get user IP
        userAgent: navigator.userAgent
      })
    });
    
    const result = await response.json();
    
    if (response.ok) {
      showSuccessMessage(result);
    } else {
      showError(result.detail);
    }
  } catch (error) {
    showError('Failed to submit consent');
  }
};
```

### **3. Check Consent Status (Admin Interface)**

```javascript
const checkConsentStatus = async (candidateId) => {
  const response = await fetch(`/secure/verification/${candidateId}/consent-status`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  const data = await response.json();
  
  if (response.ok) {
    updateConsentStatusUI(data);
  } else {
    showError(data.detail);
  }
};

const updateConsentStatusUI = (consentData) => {
  const statusElement = document.getElementById('consentStatus');
  
  switch (consentData.consentStatus) {
    case 'NOT_REQUESTED':
      statusElement.innerHTML = `
        <span class="status-pending">Consent Not Requested</span>
        <button onclick="sendConsent('${consentData.candidateId}')">
          Send Consent Request
        </button>
      `;
      break;
      
    case 'PENDING_CONSENT':
      statusElement.innerHTML = `
        <span class="status-waiting">Waiting for Consent</span>
        <p>Consent requested on: ${formatDate(consentData.consentRequestedAt)}</p>
      `;
      break;
      
    case 'CONSENT_GIVEN':
      statusElement.innerHTML = `
        <span class="status-approved">Consent Given</span>
        <p>Consent provided on: ${formatDate(consentData.consentDate)}</p>
        <button onclick="startVerification('${consentData.candidateId}')" class="btn-primary">
          Start Verification
        </button>
      `;
      break;
      
    case 'CONSENT_DENIED':
      statusElement.innerHTML = `
        <span class="status-denied">Consent Denied</span>
        <p>Response received on: ${formatDate(consentData.consentDate)}</p>
        <p>Verification cannot proceed without consent.</p>
      `;
      break;
      
    case 'TOKEN_EXPIRED':
      statusElement.innerHTML = `
        <span class="status-expired">Consent Request Expired</span>
        <button onclick="sendConsent('${consentData.candidateId}')">
          Resend Consent Request
        </button>
      `;
      break;
  }
};
```

---

## 🔒 **Security Features**

### **1. Token Security**
- **Secure Generation**: Uses `secrets.token_urlsafe(32)` for cryptographically secure tokens
- **Expiration**: Tokens expire after 48 hours
- **Single Use**: Tokens are cleared after consent submission
- **No Authentication**: Public endpoints don't require login (token-based access)

### **2. Audit Trail**
- **IP Address Logging**: Records candidate's IP address
- **User Agent Logging**: Records browser/device information
- **Timestamp Tracking**: All actions are timestamped
- **Digital Signature**: Optional candidate signature capture

### **3. Access Control**
- **Organization Boundaries**: Users can only send consent for candidates in their accessible organizations
- **Role-Based Permissions**: Different roles have different access levels
- **Activity Logging**: All consent actions are logged

---

## 🧪 **Testing Scenarios**

### **Test 1: Complete Consent Flow**
```bash
# 1. Send consent request
POST /secure/verification/507f1f77bcf86cd799439011/send-consent
{
  "verificationChecks": [
    {"name": "Employment Verification", "description": "Verify job history"}
  ]
}

# 2. Get consent details (using token from step 1)
GET /public/verification-consent/abc123def456...

# 3. Submit consent
POST /public/verification-consent/abc123def456.../submit
{
  "consentGiven": true,
  "candidateSignature": "John Doe"
}

# 4. Check consent status
GET /secure/verification/507f1f77bcf86cd799439011/consent-status
```

### **Test 2: Error Scenarios**
```bash
# Invalid candidate ID
POST /secure/verification/invalid-id/send-consent
# Expected: 400 Bad Request

# Expired token
GET /public/verification-consent/expired-token
# Expected: 404 Not Found

# Already consented
POST /public/verification-consent/used-token/submit
# Expected: ALREADY_CONSENTED status
```

---

## 🚀 **Integration with Existing Verification**

### **Before Starting Verification (Update Existing Endpoints)**

Add consent check to existing verification endpoints:

```python
# In existing verification endpoints, add this check:
async def check_consent_before_verification(candidate_id):
    candidate = await candidatesCol.find_one({"_id": ObjectId(candidate_id)})
    
    if not candidate.get("consentAcknowledged"):
        raise HTTPException(
            400, 
            "Candidate consent required before starting verification. "
            "Please send consent request first."
        )
    
    return True

# Example usage in existing verification endpoint:
@app.post("/secure/runStage")
async def runStage(body: dict = Body(...), user: dict = Depends(requireAuth)):
    candidate_id = body.get("candidateId")
    
    # Check consent before proceeding
    await check_consent_before_verification(candidate_id)
    
    # Continue with existing verification logic...
```

This consent system ensures GDPR compliance and provides candidates with full transparency about what verification checks will be performed on their data! 🎉