# Complete Verification Flow - From Start to Finish

## 🎯 Overview

This guide shows the **complete flow** from adding checks to completing them, including both **API-based** and **manual** checks.

---

## 📋 Scenario: Verify a New Candidate

**Candidate:** John Doe  
**Checks Needed:**
- ✅ PAN Verification (API)
- ✅ Aadhaar Verification (API)
- ✅ Address Verification (Manual)
- ✅ Education Check (Manual)

---

## 🚀 STEP 1: Create Candidate

### UI Action:
HR fills candidate form and clicks "Add Candidate"

### API Call:
```bash
POST /secure/addCandidate
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "phone": "9876543210",
  "panNumber": "ABCDE1234F",
  "aadhaarNumber": "123456789012",
  "address": "123 Main St, City, State",
  "organizationId": "org_789"
}
```

### Response:
```json
{
  "message": "Candidate added successfully",
  "candidateId": "cand_456",
  "candidate": {
    "_id": "cand_456",
    "firstName": "John",
    "lastName": "Doe",
    "email": "john.doe@example.com",
    "status": "PENDING"
  }
}
```

### What Happens:
- ✅ Candidate created in database
- ✅ Status set to "PENDING"
- ✅ candidateId returned: `cand_456`

---

## 🎬 STEP 2: Initiate Verification with Mixed Checks

### UI Action:
HR selects candidate and clicks "Start Verification"  
HR selects checks (both API and manual):
- [x] PAN Verification (API)
- [x] Aadhaar Verification (API)
- [x] Address Verification (Manual)
- [x] Education Check (Manual)

### API Call:
```bash
POST /secure/initiateStageVerification
Content-Type: application/json

{
  "candidateId": "cand_456",
  "organizationId": "org_789",
  "stages": {
    "primary": [
      "pan_verification",           // API check
      "aadhaar_verification",       // API check
      "address_verification",       // Manual check
      "education_check_manual"      // Manual check
    ]
  }
}
```

### Response:
```json
{
  "message": "Verification initiated successfully",
  "verificationId": "ver_123",
  "verification": {
    "_id": "ver_123",
    "candidateId": "cand_456",
    "organizationId": "org_789",
    "currentStage": "primary",
    "overallStatus": "IN_PROGRESS",
    "stages": {
      "primary": [
        {
          "check": "pan_verification",
          "status": "PENDING",
          "remarks": null,
          "submittedAt": null
        },
        {
          "check": "aadhaar_verification",
          "status": "PENDING",
          "remarks": null,
          "submittedAt": null
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
}
```

### What Happens:
- ✅ Verification record created
- ✅ All checks set to "PENDING"
- ✅ verificationId returned: `ver_123`
- ✅ Progress: 0% (0/4 completed)

---

## ⚡ STEP 3: Run API-Based Checks

### UI Action:
HR clicks "Run API Checks" button

### API Call:
```bash
POST /secure/runStage
Content-Type: application/json

{
  "verificationId": "ver_123",
  "stage": "primary"
}
```

### What Happens Behind the Scenes:

```
1. Backend receives request
   ↓
2. Loads verification record
   ↓
3. Loads candidate data
   ↓
4. Loops through ALL checks in "primary" stage
   ↓
5. For each check:
   
   IF check is API-based (pan_verification, aadhaar_verification):
      ├─ Calls run_verification() in apis.py
      ├─ run_verification() calls Surepass API
      ├─ Gets result (COMPLETED/FAILED)
      └─ Updates check status in database
   
   IF check is manual (address_verification, education_check_manual):
      ├─ Checks if required data exists
      ├─ If data missing → marks as SKIPPED/FAILED
      └─ If data exists → keeps as PENDING (waits for manual update)
   ↓
6. Returns response
```

### Response:
```json
{
  "message": "Stage completed",
  "stage": "primary",
  "verificationId": "ver_123"
}
```

### Database After API Checks:
```json
{
  "stages": {
    "primary": [
      {
        "check": "pan_verification",
        "status": "COMPLETED",              // ✅ Done by API
        "remarks": "PAN verified successfully",
        "submittedAt": "2024-01-15T10:30:00Z"
      },
      {
        "check": "aadhaar_verification",
        "status": "COMPLETED",              // ✅ Done by API
        "remarks": "Aadhaar verified successfully",
        "submittedAt": "2024-01-15T10:30:05Z"
      },
      {
        "check": "address_verification",
        "status": "PENDING",                // ⏳ Still waiting (manual)
        "remarks": null,
        "submittedAt": null
      },
      {
        "check": "education_check_manual",
        "status": "PENDING",                // ⏳ Still waiting (manual)
        "remarks": null,
        "submittedAt": null
      }
    ]
  },
  "overallStatus": "IN_PROGRESS"
}
```

### Progress Update:
- ✅ Progress: 50% (2/4 completed)
- ✅ API checks done automatically
- ⏳ Manual checks still pending

---

## 👤 STEP 4: Field Agent Completes Address Verification

### UI Action:
1. Field agent visits candidate's address
2. Agent opens verification detail page
3. Agent clicks "Mark as Complete" on "Address Verification"
4. Modal opens

### UI Form:
```
┌────────────────────────────────────────────────┐
│  Complete Check: Address Verification         │
├────────────────────────────────────────────────┤
│                                                 │
│  Status: *                                     │
│  ◉ COMPLETED                                   │
│  ○ FAILED                                      │
│  ○ IN_PROGRESS                                 │
│                                                 │
│  Remarks: *                                    │
│  ┌───────────────────────────────────────────┐│
│  │ Visited candidate's address on Jan 16.   ││
│  │ Confirmed residential address matches    ││
│  │ records. Verified with utility bill and  ││
│  │ landlord signature.                       ││
│  │ Address: 123 Main St, City, State        ││
│  └───────────────────────────────────────────┘│
│                                                 │
│  Evidence:                                     │
│  [📷 photo_evidence.jpg] [Uploaded]           │
│                                                 │
│           [Cancel]              [Submit]       │
└────────────────────────────────────────────────┘
```

### API Call:
```bash
POST /secure/updateInternalVerification
Content-Type: application/json

{
  "verificationId": "ver_123",
  "stage": "primary",
  "checkName": "address_verification",
  "status": "COMPLETED",
  "remarks": "Visited candidate's address on Jan 16, 2024. Confirmed residential address matches records. Verified with utility bill and landlord signature. Address: 123 Main St, City, State"
}
```

### Response:
```json
{
  "check": "address_verification",
  "status": "COMPLETED",
  "stageCompleted": false,    // Not all checks done yet
  "canProceed": true
}
```

### Database After Manual Update:
```json
{
  "stages": {
    "primary": [
      {
        "check": "pan_verification",
        "status": "COMPLETED",              // ✅ API
        "remarks": "PAN verified successfully",
        "submittedAt": "2024-01-15T10:30:00Z"
      },
      {
        "check": "aadhaar_verification",
        "status": "COMPLETED",              // ✅ API
        "remarks": "Aadhaar verified successfully",
        "submittedAt": "2024-01-15T10:30:05Z"
      },
      {
        "check": "address_verification",
        "status": "COMPLETED",              // ✅ Manual (just updated!)
        "remarks": "Visited candidate's address...",
        "submittedAt": "2024-01-16T14:45:00Z"
      },
      {
        "check": "education_check_manual",
        "status": "PENDING",                // ⏳ Still waiting
        "remarks": null,
        "submittedAt": null
      }
    ]
  },
  "overallStatus": "IN_PROGRESS"
}
```

### Progress Update:
- ✅ Progress: 75% (3/4 completed)
- ✅ 2 API checks done
- ✅ 1 manual check done
- ⏳ 1 manual check remaining

---

## 📚 STEP 5: HR Completes Education Check

### UI Action:
1. HR calls university to verify degree
2. HR opens verification detail page
3. HR clicks "Mark as Complete" on "Education Check"
4. Modal opens

### UI Form:
```
┌────────────────────────────────────────────────┐
│  Complete Check: Education Check (Manual)      │
├────────────────────────────────────────────────┤
│                                                 │
│  Status: *                                     │
│  ◉ COMPLETED                                   │
│  ○ FAILED                                      │
│  ○ IN_PROGRESS                                 │
│                                                 │
│  Remarks: *                                    │
│  ┌───────────────────────────────────────────┐│
│  │ Called ABC University on Jan 17, 2024.   ││
│  │ Spoke with Registrar Office.             ││
│  │ Confirmed:                                ││
│  │ - Degree: Bachelor of Science            ││
│  │ - Year: 2020                              ││
│  │ - Roll No: 12345                          ││
│  │ - Status: Graduated                       ││
│  │ Contact: registrar@university.edu         ││
│  └───────────────────────────────────────────┘│
│                                                 │
│           [Cancel]              [Submit]       │
└────────────────────────────────────────────────┘
```

### API Call:
```bash
POST /secure/updateInternalVerification
Content-Type: application/json

{
  "verificationId": "ver_123",
  "stage": "primary",
  "checkName": "education_check_manual",
  "status": "COMPLETED",
  "remarks": "Called ABC University on Jan 17, 2024. Spoke with Registrar Office. Confirmed: Degree: Bachelor of Science, Year: 2020, Roll No: 12345, Status: Graduated. Contact: registrar@university.edu"
}
```

### Response:
```json
{
  "check": "education_check_manual",
  "status": "COMPLETED",
  "stageCompleted": true,     // ✅ ALL checks done!
  "canProceed": true
}
```

### Database After Final Check:
```json
{
  "stages": {
    "primary": [
      {
        "check": "pan_verification",
        "status": "COMPLETED",              // ✅ API
        "remarks": "PAN verified successfully",
        "submittedAt": "2024-01-15T10:30:00Z"
      },
      {
        "check": "aadhaar_verification",
        "status": "COMPLETED",              // ✅ API
        "remarks": "Aadhaar verified successfully",
        "submittedAt": "2024-01-15T10:30:05Z"
      },
      {
        "check": "address_verification",
        "status": "COMPLETED",              // ✅ Manual
        "remarks": "Visited candidate's address...",
        "submittedAt": "2024-01-16T14:45:00Z"
      },
      {
        "check": "education_check_manual",
        "status": "COMPLETED",              // ✅ Manual (just completed!)
        "remarks": "Called ABC University...",
        "submittedAt": "2024-01-17T11:20:00Z"
      }
    ]
  },
  "overallStatus": "IN_PROGRESS",  // Still IN_PROGRESS (not final stage)
  "currentStage": "primary"
}
```

### Progress Update:
- ✅ Progress: 100% (4/4 completed)
- ✅ Primary stage COMPLETED
- ✅ All checks done (2 API + 2 Manual)
- ✅ Ready for next stage (if needed)

---

## 📊 Visual Timeline

```
Day 1 - 10:00 AM
├─ HR creates candidate
└─ Status: PENDING

Day 1 - 10:15 AM
├─ HR initiates verification
├─ Adds 4 checks (2 API + 2 Manual)
└─ Status: IN_PROGRESS (0%)

Day 1 - 10:20 AM
├─ HR clicks "Run API Checks"
├─ PAN verified ✅ (API - 2 seconds)
├─ Aadhaar verified ✅ (API - 3 seconds)
└─ Status: IN_PROGRESS (50%)

Day 2 - 2:45 PM
├─ Field agent visits address
├─ Agent marks address check complete ✅
└─ Status: IN_PROGRESS (75%)

Day 3 - 11:20 AM
├─ HR calls university
├─ HR marks education check complete ✅
└─ Status: IN_PROGRESS (100%)
    Primary stage COMPLETED!
```

---

## 🔄 Complete Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    COMPLETE FLOW                             │
└─────────────────────────────────────────────────────────────┘

1. CREATE CANDIDATE
   POST /secure/addCandidate
   ↓
   candidateId: cand_456
   status: PENDING

2. INITIATE VERIFICATION (Mixed Checks)
   POST /secure/initiateStageVerification
   {
     "stages": {
       "primary": [
         "pan_verification",        // API
         "aadhaar_verification",    // API
         "address_verification",    // Manual
         "education_check_manual"   // Manual
       ]
     }
   }
   ↓
   verificationId: ver_123
   All checks: PENDING
   Progress: 0%

3. RUN API CHECKS
   POST /secure/runStage
   {
     "verificationId": "ver_123",
     "stage": "primary"
   }
   ↓
   Backend automatically:
   ├─ Runs pan_verification → COMPLETED ✅
   ├─ Runs aadhaar_verification → COMPLETED ✅
   ├─ Skips address_verification (manual)
   └─ Skips education_check_manual (manual)
   ↓
   Progress: 50% (2/4)

4. MANUAL CHECK #1 (Address)
   POST /secure/updateInternalVerification
   {
     "checkName": "address_verification",
     "status": "COMPLETED",
     "remarks": "Visited site..."
   }
   ↓
   address_verification: COMPLETED ✅
   Progress: 75% (3/4)

5. MANUAL CHECK #2 (Education)
   POST /secure/updateInternalVerification
   {
     "checkName": "education_check_manual",
     "status": "COMPLETED",
     "remarks": "Called university..."
   }
   ↓
   education_check_manual: COMPLETED ✅
   Progress: 100% (4/4)
   Stage: COMPLETED ✅

6. FINAL STATUS
   All checks completed!
   ├─ 2 API checks ✅
   ├─ 2 Manual checks ✅
   └─ Primary stage COMPLETED ✅
```

---

## 🎯 Key Points

### API Checks (Automatic):
- ✅ Run via `/secure/runStage`
- ✅ Execute in seconds
- ✅ Call external APIs (Surepass)
- ✅ Update automatically

### Manual Checks (Human):
- ✅ Run via `/secure/updateInternalVerification`
- ✅ Take hours/days
- ✅ Require human work (visits, calls)
- ✅ Update when human completes

### Mixed Stage:
- ✅ Can have both API and manual checks
- ✅ API checks run first (fast)
- ✅ Manual checks updated later (slow)
- ✅ Progress updates in real-time
- ✅ Stage completes when ALL checks done

### Progress Calculation:
```javascript
completionPercentage = (completedChecks / totalChecks) * 100

Example:
- Total: 4 checks
- Completed: 2 checks
- Percentage: (2/4) * 100 = 50%
```

---

## 📝 Summary

**3 Main Actions:**

1. **Initiate** → Creates verification with all checks
   ```bash
   POST /secure/initiateStageVerification
   ```

2. **Run API Checks** → Executes automatic checks
   ```bash
   POST /secure/runStage
   ```

3. **Update Manual Checks** → HR/Agent marks as complete
   ```bash
   POST /secure/updateInternalVerification
   ```

**Result:**
- ✅ API checks complete in seconds
- ✅ Manual checks complete when humans finish
- ✅ Progress tracked in real-time
- ✅ Stage completes when all checks done
- ✅ System handles everything automatically

That's the complete flow! 🎉
