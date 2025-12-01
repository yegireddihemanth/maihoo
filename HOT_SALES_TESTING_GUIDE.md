# Hot Sales Organization - Complete Testing Guide

## 🏢 Organization Details

```json
{
  "organizationName": "hot sales",
  "spocName": "hemanth",
  "mainDomain": "hotsales.com",
  "subDomain": "hotsales.bgvapp.in",
  "email": "vamsivakada163@gmail.com",
  "phone": "8331086719",
  "gstNumber": "29ABLDE1234F1Z5",
  "services": [
    {
      "serviceName": "Employment Verification",
      "price": 120.0
    },
    {
      "serviceName": "Education Verification",
      "price": 100.0
    }
  ],
  "logoUrl": "https://hotsales.bgvapp.in/logos/hotsales.png",
  "credentials": {
    "totalAllowed": 5,
    "used": 0
  }
}
```

---

## 🚀 STEP-BY-STEP TESTING

### STEP 1: Login as SUPER_ADMIN

**Endpoint:**
```
POST {{base_url}}/auth/login
```

**Body:**
```json
{
  "email": "your-super-admin@example.com",
  "password": "your-password"
}
```

**Expected Response:**
```json
{
  "userName": "Super Admin",
  "email": "your-super-admin@example.com",
  "role": "SUPER_ADMIN",
  "organizationId": "existing_org_id",
  "session": "created",
  "token": "eyJhbGc..."
}
```

**✅ Save:** `token` for next requests

---

### STEP 2: Create Hot Sales Organization

**Endpoint:**
```
POST {{base_url}}/secure/registerOrganization
Authorization: Bearer {{token}}
```

**Body:**
```json
{
  "organizationName": "hot sales",
  "spocName": "hemanth",
  "mainDomain": "hotsales.com",
  "subDomain": "hotsales.bgvapp.in",
  "email": "vamsivakada163@gmail.com",
  "phone": "8331086719",
  "gstNumber": "29ABLDE1234F1Z5",
  "services": [
    {
      "serviceName": "Employment Verification",
      "price": 120.0
    },
    {
      "serviceName": "Education Verification",
      "price": 100.0
    }
  ],
  "logoUrl": "https://hotsales.bgvapp.in/logos/hotsales.png",
  "credentials": {
    "totalAllowed": 5,
    "used": 0
  }
}
```

**Expected Response:**
```json
{
  "message": "Organization registered successfully",
  "organizationId": "674abc123def456789",
  "organizationName": "hot sales",
  "spocEmail": "vamsivakada163@gmail.com",
  "defaultPassword": "Welcome1",
  "note": "SPOC can now log in and add HR/Admin users if needed."
}
```

**✅ Save:**
- `organizationId`: `674abc123def456789`
- SPOC Email: `vamsivakada163@gmail.com`
- SPOC Password: `Welcome1`

**📧 Email Sent:**
An email will be sent to `vamsivakada163@gmail.com` with:
- Login credentials
- Organization details
- Services enabled
- Default password

---

### STEP 3: Login as Hot Sales SPOC

**Endpoint:**
```
POST {{base_url}}/auth/login
```

**Body:**
```json
{
  "email": "vamsivakada163@gmail.com",
  "password": "Welcome1"
}
```

**Expected Response:**
```json
{
  "userName": "hemanth",
  "email": "vamsivakada163@gmail.com",
  "role": "SPOC",
  "organizationId": "674abc123def456789",
  "organizationName": "hot sales",
  "phoneNumber": "8331086719",
  "isSuperAdmin": false,
  "session": "created",
  "token": "eyJhbGc...",
  "permissions": [
    "organization:view",
    "organization:update",
    "employee:create",
    "verification:view",
    "verification:assign",
    "dashboard:view",
    "users:manage"
  ],
  "services": [
    {
      "serviceName": "Employment Verification",
      "price": 120.0
    },
    {
      "serviceName": "Education Verification",
      "price": 100.0
    }
  ]
}
```

**✅ Save:** New `token` for Hot Sales SPOC

---

### STEP 4: Add Candidate (as Hot Sales SPOC)

**Endpoint:**
```
POST {{base_url}}/secure/addCandidate
Authorization: Bearer {{spoc_token}}
```

**Body:**
```json
{
  "firstName": "Rajesh",
  "lastName": "Kumar",
  "email": "rajesh.kumar@example.com",
  "phone": "9876543210",
  "panNumber": "ABCDE1234F",
  "aadhaarNumber": "123456789012",
  "uanNumber": "101234567890",
  "address": "Plot 123, Sector 45, Hyderabad, Telangana 500081",
  "organizationId": "674abc123def456789"
}
```

**Expected Response:**
```json
{
  "message": "Candidate added successfully",
  "candidateId": "675xyz789abc123456",
  "candidate": {
    "_id": "675xyz789abc123456",
    "firstName": "Rajesh",
    "lastName": "Kumar",
    "email": "rajesh.kumar@example.com",
    "phone": "9876543210",
    "panNumber": "ABCDE1234F",
    "aadhaarNumber": "123456789012",
    "uanNumber": "101234567890",
    "address": "Plot 123, Sector 45, Hyderabad, Telangana 500081",
    "organizationId": "674abc123def456789",
    "status": "PENDING",
    "createdBy": "vamsivakada163@gmail.com"
  }
}
```

**✅ Save:** `candidateId`: `675xyz789abc123456`

---

### STEP 5: Initiate Verification (Mixed Checks)

**Endpoint:**
```
POST {{base_url}}/secure/initiateStageVerification
Authorization: Bearer {{spoc_token}}
```

**Body:**
```json
{
  "candidateId": "675xyz789abc123456",
  "organizationId": "674abc123def456789",
  "stages": {
    "primary": [
      "pan_verification",
      "aadhaar_verification",
      "employment_history",
      "address_verification",
      "education_check_manual"
    ]
  }
}
```

**Expected Response:**
```json
{
  "message": "Verification initiated successfully",
  "verificationId": "676ver123abc456def",
  "verification": {
    "_id": "676ver123abc456def",
    "candidateId": "675xyz789abc123456",
    "organizationId": "674abc123def456789",
    "currentStage": "primary",
    "overallStatus": "IN_PROGRESS",
    "initiatedBy": "vamsivakada163@gmail.com",
    "stages": {
      "primary": [
        {
          "check": "pan_verification",
          "status": "PENDING",
          "remarks": null
        },
        {
          "check": "aadhaar_verification",
          "status": "PENDING",
          "remarks": null
        },
        {
          "check": "employment_history",
          "status": "PENDING",
          "remarks": null
        },
        {
          "check": "address_verification",
          "status": "PENDING",
          "remarks": null
        },
        {
          "check": "education_check_manual",
          "status": "PENDING",
          "remarks": null
        }
      ]
    }
  }
}
```

**✅ Save:** `verificationId`: `676ver123abc456def`

**📊 Progress:** 0% (0/5 checks completed)

---

### STEP 6: Run API Checks

**Endpoint:**
```
POST {{base_url}}/secure/runStage
Authorization: Bearer {{spoc_token}}
```

**Body:**
```json
{
  "verificationId": "676ver123abc456def",
  "stage": "primary"
}
```

**Expected Response:**
```json
{
  "message": "Stage completed",
  "stage": "primary",
  "verificationId": "676ver123abc456def"
}
```

**⏱️ Processing Time:** ~10-15 seconds

**What Happens:**
- ✅ PAN Verification → Calls Surepass API → COMPLETED
- ✅ Aadhaar Verification → Calls Surepass API → COMPLETED
- ✅ Employment History → Calls Surepass API → COMPLETED
- ⏳ Address Verification → Manual check → PENDING
- ⏳ Education Check → Manual check → PENDING

**📊 Progress:** 60% (3/5 checks completed)

---

### STEP 7: Check Verification Status

**Endpoint:**
```
GET {{base_url}}/secure/getVerificationById/676ver123abc456def
Authorization: Bearer {{spoc_token}}
```

**Expected Response:**
```json
{
  "_id": "676ver123abc456def",
  "candidateId": "675xyz789abc123456",
  "candidateName": "Rajesh Kumar",
  "organizationId": "674abc123def456789",
  "organizationName": "hot sales",
  "currentStage": "primary",
  "overallStatus": "IN_PROGRESS",
  "stages": {
    "primary": [
      {
        "check": "pan_verification",
        "status": "COMPLETED",
        "remarks": "PAN verified successfully",
        "submittedAt": "2024-01-15T10:30:00Z"
      },
      {
        "check": "aadhaar_verification",
        "status": "COMPLETED",
        "remarks": "Aadhaar verified successfully",
        "submittedAt": "2024-01-15T10:30:05Z"
      },
      {
        "check": "employment_history",
        "status": "COMPLETED",
        "remarks": "Employment history verified",
        "submittedAt": "2024-01-15T10:30:10Z"
      },
      {
        "check": "address_verification",
        "status": "PENDING",
        "remarks": null,
        "submittedAt": null
      },
      {
        "check": "education_check_manual",
        "status": "PENDING",
        "remarks": null,
        "submittedAt": null
      }
    ]
  }
}
```

**📊 Progress:** 60% (3/5 checks completed)

---

### STEP 8: Complete Address Verification (Manual)

**Endpoint:**
```
POST {{base_url}}/secure/updateInternalVerification
Authorization: Bearer {{spoc_token}}
```

**Body:**
```json
{
  "verificationId": "676ver123abc456def",
  "stage": "primary",
  "checkName": "address_verification",
  "status": "COMPLETED",
  "remarks": "Field agent visited Plot 123, Sector 45, Hyderabad on Jan 16, 2024. Confirmed residential address matches records. Verified with electricity bill and landlord signature. Property is a 2BHK apartment in a gated community."
}
```

**Expected Response:**
```json
{
  "check": "address_verification",
  "status": "COMPLETED",
  "stageCompleted": false,
  "canProceed": true
}
```

**📊 Progress:** 80% (4/5 checks completed)

---

### STEP 9: Complete Education Verification (Manual)

**Endpoint:**
```
POST {{base_url}}/secure/updateInternalVerification
Authorization: Bearer {{spoc_token}}
```

**Body:**
```json
{
  "verificationId": "676ver123abc456def",
  "stage": "primary",
  "checkName": "education_check_manual",
  "status": "COMPLETED",
  "remarks": "Called JNTU Hyderabad on Jan 17, 2024. Spoke with Registrar Office (Phone: 040-23158661). Confirmed: Degree: Bachelor of Technology (Computer Science), Year: 2018, Roll No: 15R11A0501, Status: Graduated with First Class. Certificate verified via university portal."
}
```

**Expected Response:**
```json
{
  "check": "education_check_manual",
  "status": "COMPLETED",
  "stageCompleted": true,
  "canProceed": true
}
```

**📊 Progress:** 100% (5/5 checks completed)
**🎉 PRIMARY STAGE COMPLETED!**

---

### STEP 10: View Dashboard (Hot Sales)

**Endpoint:**
```
GET {{base_url}}/dashboard?organizationId=674abc123def456789
Authorization: Bearer {{spoc_token}}
```

**Expected Response:**
```json
{
  "role": "SPOC",
  "stats": {
    "filteredByOrganization": "674abc123def456789",
    "totalEmployees": 1,
    "totalRequests": 1,
    "ongoingVerifications": 0,
    "completedVerifications": 1,
    "failedVerifications": 0,
    "stageBreakdown": {
      "primary": 1,
      "secondary": 0,
      "final": 0
    }
  }
}
```

---

## 📋 Complete Postman Collection

### Environment Variables:

```
base_url = https://your-api-domain.com
super_admin_token = (from Step 1)
hot_sales_org_id = 674abc123def456789
hot_sales_spoc_token = (from Step 3)
candidate_id = 675xyz789abc123456
verification_id = 676ver123abc456def
```

### Collection Structure:

```
Hot Sales Testing
├── 1. Authentication
│   ├── Login as Super Admin
│   └── Login as Hot Sales SPOC
├── 2. Organization Setup
│   └── Create Hot Sales Organization
├── 3. Candidate Management
│   └── Add Candidate (Rajesh Kumar)
├── 4. Verification Flow
│   ├── Initiate Verification
│   ├── Run API Checks
│   ├── Check Status
│   ├── Update Address Verification
│   ├── Update Education Verification
│   └── Final Status Check
└── 5. Dashboard
    └── View Hot Sales Dashboard
```

---

## 🎯 Testing Checklist

- [ ] Super Admin login successful
- [ ] Hot Sales organization created
- [ ] Organization ID saved: `674abc123def456789`
- [ ] SPOC email received: `vamsivakada163@gmail.com`
- [ ] SPOC login successful with `Welcome1`
- [ ] SPOC token saved
- [ ] Candidate Rajesh Kumar created
- [ ] Candidate ID saved: `675xyz789abc123456`
- [ ] Verification initiated
- [ ] Verification ID saved: `676ver123abc456def`
- [ ] API checks run (60% complete)
- [ ] Address verification completed (80% complete)
- [ ] Education verification completed (100% complete)
- [ ] Primary stage completed
- [ ] Dashboard shows correct stats

---

## 📊 Expected Timeline

```
Day 1, 10:00 AM  →  Create organization
Day 1, 10:05 AM  →  SPOC receives email
Day 1, 10:10 AM  →  SPOC logs in
Day 1, 10:15 AM  →  Add candidate Rajesh Kumar
Day 1, 10:20 AM  →  Initiate verification (0%)
Day 1, 10:25 AM  →  Run API checks (60% in 15 seconds!)
Day 2, 2:45 PM   →  Complete address check (80%)
Day 3, 11:20 AM  →  Complete education check (100%) ✅
```

---

## 🔐 Login Credentials

### Super Admin:
- Email: `your-super-admin@example.com`
- Password: `your-password`

### Hot Sales SPOC:
- Email: `vamsivakada163@gmail.com`
- Password: `Welcome1` (change after first login)
- Organization: `hot sales`
- Organization ID: `674abc123def456789`

---

## 📧 Email Notifications

### 1. Organization Welcome Email
**To:** vamsivakada163@gmail.com  
**Subject:** Welcome to BGVApp - hot sales Registration Successful  
**Contains:**
- Login credentials
- Organization details
- Services: Employment Verification (₹120), Education Verification (₹100)
- User limit: 5 users
- Default password: Welcome1

---

## 🎉 Success Criteria

✅ Organization created successfully  
✅ SPOC can login  
✅ SPOC can add candidates  
✅ SPOC can initiate verifications  
✅ API checks run automatically  
✅ Manual checks can be updated  
✅ Progress tracked correctly  
✅ Dashboard shows accurate stats  

---

## 💡 Next Steps

1. **Change SPOC Password:**
   ```
   POST /secure/changePassword
   {
     "oldPassword": "Welcome1",
     "newPassword": "YourNewSecurePassword"
   }
   ```

2. **Add HR Users:**
   ```
   POST /secure/addHelper
   {
     "userName": "HR Manager",
     "email": "hr@hotsales.com",
     "role": "ORG_HR",
     "phoneNumber": "9876543211"
   }
   ```

3. **Add More Candidates:**
   - Repeat Step 4 with different candidate details

4. **Run More Verifications:**
   - Test with different check combinations
   - Test secondary and final stages

---

That's your complete testing guide for Hot Sales organization! 🚀
