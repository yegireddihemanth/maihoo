# Postman Testing Guide - Complete Verification Flow

## 🎯 Overview

This guide will walk you through testing the complete verification flow using Postman, including both API and manual checks.

---

## 📋 Prerequisites

1. **Postman** installed
2. **Backend server** running
3. **Valid user credentials** (SUPER_ADMIN, SPOC, or ORG_HR)

---

## 🔐 STEP 0: Login and Get Session Token

### Request:
```
POST {{base_url}}/auth/login
Content-Type: application/json
```

### Body:
```json
{
  "email": "your-email@example.com",
  "password": "your-password"
}
```

### Response:
```json
{
  "userName": "Admin User",
  "email": "admin@example.com",
  "role": "SUPER_ADMIN",
  "organizationId": "org_789",
  "session": "created",
  "token": "eyJhbGc..."
}
```

### ⚠️ Important:
**Save the `token` from response!** You'll need it for all subsequent requests.

### Postman Setup:
1. Go to **Tests** tab in Postman
2. Add this script to auto-save token:
```javascript
if (pm.response.code === 200) {
    var jsonData = pm.response.json();
    pm.environment.set("auth_token", jsonData.token);
    pm.environment.set("organizationId", jsonData.organizationId);
}
```

---

## 📝 STEP 1: Create Candidate

### Request:
```
POST {{base_url}}/secure/addCandidate
Content-Type: application/json
Authorization: Bearer {{auth_token}}
```

### Body:
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "phone": "9876543210",
  "panNumber": "ABCDE1234F",
  "aadhaarNumber": "123456789012",
  "address": "123 Main St, City, State 12345",
  "organizationId": "{{organizationId}}"
}
```

### Expected Response:
```json
{
  "message": "Candidate added successfully",
  "candidateId": "673abc123def456789",
  "candidate": {
    "_id": "673abc123def456789",
    "firstName": "John",
    "lastName": "Doe",
    "email": "john.doe@example.com",
    "status": "PENDING"
  }
}
```

### ✅ Save candidateId:
In **Tests** tab:
```javascript
if (pm.response.code === 201 || pm.response.code === 200) {
    var jsonData = pm.response.json();
    pm.environment.set("candidateId", jsonData.candidateId);
}
```

---

## 🎬 STEP 2: Initiate Verification (Mixed Checks)

### Request:
```
POST {{base_url}}/secure/initiateStageVerification
Content-Type: application/json
Authorization: Bearer {{auth_token}}
```

### Body (Mixed: 2 API + 2 Manual):
```json
{
  "candidateId": "{{candidateId}}",
  "organizationId": "{{organizationId}}",
  "stages": {
    "primary": [
      "pan_verification",
      "aadhaar_verification",
      "address_verification",
      "education_check_manual"
    ]
  }
}
```

### Expected Response:
```json
{
  "message": "Verification initiated successfully",
  "verificationId": "ver_abc123",
  "verification": {
    "_id": "ver_abc123",
    "candidateId": "673abc123def456789",
    "currentStage": "primary",
    "overallStatus": "IN_PROGRESS",
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

### ✅ Save verificationId:
In **Tests** tab:
```javascript
if (pm.response.code === 201 || pm.response.code === 200) {
    var jsonData = pm.response.json();
    pm.environment.set("verificationId", jsonData.verificationId);
}
```

### 📊 Check Status:
All checks should be **PENDING** (0% complete)

---

## ⚡ STEP 3: Run API Checks

### Request:
```
POST {{base_url}}/secure/runStage
Content-Type: application/json
Authorization: Bearer {{auth_token}}
```

### Body:
```json
{
  "verificationId": "{{verificationId}}",
  "stage": "primary"
}
```

### Expected Response:
```json
{
  "message": "Stage completed",
  "stage": "primary",
  "verificationId": "ver_abc123"
}
```

### ⏱️ What Happens:
- Backend calls Surepass APIs for PAN and Aadhaar
- Takes ~5-10 seconds
- Manual checks remain PENDING

---

## 🔍 STEP 4: Check Verification Status

### Request:
```
GET {{base_url}}/secure/getVerificationById/{{verificationId}}
Authorization: Bearer {{auth_token}}
```

### Expected Response:
```json
{
  "_id": "ver_abc123",
  "candidateId": "673abc123def456789",
  "currentStage": "primary",
  "overallStatus": "IN_PROGRESS",
  "stages": {
    "primary": [
      {
        "check": "pan_verification",
        "status": "COMPLETED",                    // ✅ Done by API
        "remarks": "PAN verified successfully",
        "submittedAt": "2024-01-15T10:30:00Z"
      },
      {
        "check": "aadhaar_verification",
        "status": "COMPLETED",                    // ✅ Done by API
        "remarks": "Aadhaar verified successfully",
        "submittedAt": "2024-01-15T10:30:05Z"
      },
      {
        "check": "address_verification",
        "status": "PENDING",                      // ⏳ Waiting for manual
        "remarks": null,
        "submittedAt": null
      },
      {
        "check": "education_check_manual",
        "status": "PENDING",                      // ⏳ Waiting for manual
        "remarks": null,
        "submittedAt": null
      }
    ]
  }
}
```

### 📊 Progress:
- **50% complete** (2/4 checks done)
- API checks: ✅ COMPLETED
- Manual checks: ⏳ PENDING

---

## 👤 STEP 5: Complete Manual Check #1 (Address)

### Request:
```
POST {{base_url}}/secure/updateInternalVerification
Content-Type: application/json
Authorization: Bearer {{auth_token}}
```

### Body:
```json
{
  "verificationId": "{{verificationId}}",
  "stage": "primary",
  "checkName": "address_verification",
  "status": "COMPLETED",
  "remarks": "Visited candidate's address on Jan 16, 2024. Confirmed residential address matches records. Verified with utility bill and landlord signature. Address: 123 Main St, City, State 12345"
}
```

### Expected Response:
```json
{
  "check": "address_verification",
  "status": "COMPLETED",
  "stageCompleted": false,    // Not all checks done yet
  "canProceed": true
}
```

### 📊 Progress:
- **75% complete** (3/4 checks done)

---

## 📚 STEP 6: Complete Manual Check #2 (Education)

### Request:
```
POST {{base_url}}/secure/updateInternalVerification
Content-Type: application/json
Authorization: Bearer {{auth_token}}
```

### Body:
```json
{
  "verificationId": "{{verificationId}}",
  "stage": "primary",
  "checkName": "education_check_manual",
  "status": "COMPLETED",
  "remarks": "Called ABC University on Jan 17, 2024. Spoke with Registrar Office. Confirmed: Degree: Bachelor of Science, Year: 2020, Roll No: 12345, Status: Graduated. Contact: registrar@university.edu"
}
```

### Expected Response:
```json
{
  "check": "education_check_manual",
  "status": "COMPLETED",
  "stageCompleted": true,     // ✅ ALL checks done!
  "canProceed": true
}
```

### 📊 Progress:
- **100% complete** (4/4 checks done)
- **Primary stage COMPLETED!** 🎉

---

## ✅ STEP 7: Verify Final Status

### Request:
```
GET {{base_url}}/secure/getVerificationById/{{verificationId}}
Authorization: Bearer {{auth_token}}
```

### Expected Response:
```json
{
  "_id": "ver_abc123",
  "candidateId": "673abc123def456789",
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
        "check": "address_verification",
        "status": "COMPLETED",
        "remarks": "Visited candidate's address...",
        "submittedAt": "2024-01-16T14:45:00Z"
      },
      {
        "check": "education_check_manual",
        "status": "COMPLETED",
        "remarks": "Called ABC University...",
        "submittedAt": "2024-01-17T11:20:00Z"
      }
    ]
  }
}
```

### ✅ All Checks Complete!
- 2 API checks ✅
- 2 Manual checks ✅
- Primary stage 100% ✅

---

## 📋 Postman Collection Setup

### Create Environment Variables:

1. Click **Environments** in Postman
2. Create new environment: "BGV Testing"
3. Add variables:

```
base_url: https://your-api-domain.com
auth_token: (will be set automatically)
organizationId: (will be set automatically)
candidateId: (will be set automatically)
verificationId: (will be set automatically)
```

### Create Collection:

1. **Folder 1: Authentication**
   - Login

2. **Folder 2: Candidate Management**
   - Add Candidate

3. **Folder 3: Verification Flow**
   - Initiate Verification
   - Run API Checks
   - Get Verification Status
   - Update Manual Check (Address)
   - Update Manual Check (Education)
   - Get Final Status

---

## 🧪 Testing Scenarios

### Scenario 1: Only API Checks
```json
{
  "stages": {
    "primary": [
      "pan_verification",
      "aadhaar_verification"
    ]
  }
}
```
Then run: `POST /secure/runStage`
Result: 100% complete immediately

### Scenario 2: Only Manual Checks
```json
{
  "stages": {
    "primary": [
      "address_verification",
      "education_check_manual"
    ]
  }
}
```
Then update each manually:
- `POST /secure/updateInternalVerification` (address)
- `POST /secure/updateInternalVerification` (education)

### Scenario 3: Mixed (Recommended)
```json
{
  "stages": {
    "primary": [
      "pan_verification",
      "address_verification"
    ]
  }
}
```
1. Run API checks: `POST /secure/runStage` (50% done)
2. Update manual: `POST /secure/updateInternalVerification` (100% done)

---

## 🔍 Troubleshooting

### Issue 1: "No session cookie"
**Solution:** Make sure you're sending the token in Authorization header:
```
Authorization: Bearer {{auth_token}}
```

### Issue 2: "Candidate not found"
**Solution:** Check that candidateId is correct:
```
GET {{base_url}}/secure/getCandidateById/{{candidateId}}
```

### Issue 3: "Verification not found"
**Solution:** Check that verificationId is correct:
```
GET {{base_url}}/secure/getVerificationById/{{verificationId}}
```

### Issue 4: "Check already completed"
**Solution:** You can't update a check that's already COMPLETED. Check status first.

### Issue 5: API checks fail with "Missing required field"
**Solution:** Make sure candidate has required data:
- PAN check needs: `panNumber`
- Aadhaar check needs: `aadhaarNumber`
- Employment check needs: `uanNumber`

---

## 📊 Expected Progress Flow

```
Step 1: Create Candidate
   Status: PENDING
   Progress: N/A

Step 2: Initiate Verification
   Status: IN_PROGRESS
   Progress: 0% (0/4)

Step 3: Run API Checks
   Status: IN_PROGRESS
   Progress: 50% (2/4)
   Time: ~5 seconds

Step 4: Update Manual Check #1
   Status: IN_PROGRESS
   Progress: 75% (3/4)

Step 5: Update Manual Check #2
   Status: IN_PROGRESS
   Progress: 100% (4/4)
   Stage: COMPLETED ✅
```

---

## 🎯 Quick Test Checklist

- [ ] Login successful
- [ ] Token saved in environment
- [ ] Candidate created
- [ ] candidateId saved
- [ ] Verification initiated
- [ ] verificationId saved
- [ ] API checks run successfully
- [ ] Status shows 50% complete
- [ ] Manual check #1 updated
- [ ] Status shows 75% complete
- [ ] Manual check #2 updated
- [ ] Status shows 100% complete
- [ ] All checks show COMPLETED

---

## 💡 Pro Tips

1. **Use Environment Variables** - Makes testing easier
2. **Use Tests Tab** - Auto-save IDs from responses
3. **Check Status Often** - Use GET endpoint to verify progress
4. **Test Error Cases** - Try invalid IDs, missing fields, etc.
5. **Save Collection** - Export and share with team

---

## 📝 Sample Postman Tests Scripts

### For Login:
```javascript
pm.test("Login successful", function () {
    pm.response.to.have.status(200);
    var jsonData = pm.response.json();
    pm.expect(jsonData.token).to.exist;
    pm.environment.set("auth_token", jsonData.token);
    pm.environment.set("organizationId", jsonData.organizationId);
});
```

### For Create Candidate:
```javascript
pm.test("Candidate created", function () {
    pm.response.to.have.status(201);
    var jsonData = pm.response.json();
    pm.expect(jsonData.candidateId).to.exist;
    pm.environment.set("candidateId", jsonData.candidateId);
});
```

### For Initiate Verification:
```javascript
pm.test("Verification initiated", function () {
    pm.response.to.have.status(201);
    var jsonData = pm.response.json();
    pm.expect(jsonData.verificationId).to.exist;
    pm.environment.set("verificationId", jsonData.verificationId);
});
```

### For Check Status:
```javascript
pm.test("Check completion percentage", function () {
    var jsonData = pm.response.json();
    var stages = jsonData.stages.primary;
    var completed = stages.filter(c => c.status === "COMPLETED").length;
    var total = stages.length;
    var percentage = (completed / total) * 100;
    console.log(`Progress: ${percentage}% (${completed}/${total})`);
});
```

---

That's everything you need to test the complete flow in Postman! 🚀
