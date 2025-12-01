# UI Requirements for Manual Verification System

## 🎯 Overview

The UI needs to allow users to:
1. View candidates with pending manual verifications
2. See which checks need to be completed
3. Update individual checks as they complete them
4. Track progress in real-time

---

## 📋 Required UI Components

### 1. **Verification List Page**

Shows all verifications with manual checks pending.

#### API Call:
```javascript
GET /secure/getVerificationsByOrganization?organizationId={orgId}
```

#### What You Get:
```json
{
  "verifications": [
    {
      "_id": "ver_123",
      "candidateId": "cand_456",
      "candidateName": "John Doe",
      "currentStage": "primary",
      "overallStatus": "IN_PROGRESS",
      "completionPercentage": 50,
      "totalChecks": 4,
      "completedChecks": 2,
      "inProgressChecks": 0,
      "failedChecks": 0,
      "stages": {
        "primary": [
          {"check": "pan_verification", "status": "COMPLETED"},
          {"check": "address_verification", "status": "PENDING"},
          {"check": "education_check_manual", "status": "PENDING"}
        ]
      }
    }
  ]
}
```

#### UI Display:
```
┌─────────────────────────────────────────────────────────┐
│  Manual Verifications                                   │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  John Doe                              [50% Complete]   │
│  Stage: Primary                        ████████░░░░░░   │
│  Status: IN_PROGRESS                                    │
│  Checks: 2/4 completed                                  │
│                                        [View Details →] │
│                                                          │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Jane Smith                            [75% Complete]   │
│  Stage: Secondary                      ███████████░░░   │
│  Status: IN_PROGRESS                                    │
│  Checks: 3/4 completed                                  │
│                                        [View Details →] │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

### 2. **Verification Detail Page**

Shows all checks for a specific candidate with ability to update.

#### API Call:
```javascript
GET /secure/getVerificationById/{verificationId}
```

#### What You Get:
```json
{
  "_id": "ver_123",
  "candidateId": "cand_456",
  "candidateName": "John Doe",
  "candidateEmail": "john@example.com",
  "candidatePhone": "9876543210",
  "currentStage": "primary",
  "overallStatus": "IN_PROGRESS",
  "stages": {
    "primary": [
      {
        "check": "pan_verification",
        "status": "COMPLETED",
        "remarks": "PAN verified via API",
        "submittedAt": "2024-01-15T10:30:00Z"
      },
      {
        "check": "aadhaar_verification",
        "status": "COMPLETED",
        "remarks": "Aadhaar verified via API",
        "submittedAt": "2024-01-15T10:30:05Z"
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

#### UI Display:
```
┌─────────────────────────────────────────────────────────┐
│  ← Back to List                                         │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Candidate: John Doe                                    │
│  Email: john@example.com                                │
│  Phone: 9876543210                                      │
│  Stage: Primary                        [50% Complete]   │
│                                                          │
├─────────────────────────────────────────────────────────┤
│  Verification Checks                                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ✅ PAN Verification                   [COMPLETED]      │
│     Remarks: PAN verified via API                       │
│     Completed: Jan 15, 2024 10:30 AM                    │
│                                                          │
│  ✅ Aadhaar Verification               [COMPLETED]      │
│     Remarks: Aadhaar verified via API                   │
│     Completed: Jan 15, 2024 10:30 AM                    │
│                                                          │
│  ⏳ Address Verification               [PENDING]        │
│     [Mark as Complete]                                  │
│                                                          │
│  ⏳ Education Check (Manual)           [PENDING]        │
│     [Mark as Complete]                                  │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

### 3. **Update Check Modal/Form**

When user clicks "Mark as Complete" on a pending check.

#### UI Form Fields:
```
┌─────────────────────────────────────────────────────────┐
│  Complete Check: Address Verification                   │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Status: *                                              │
│  ○ COMPLETED                                            │
│  ○ FAILED                                               │
│  ○ IN_PROGRESS                                          │
│                                                          │
│  Remarks: *                                             │
│  ┌─────────────────────────────────────────────────┐   │
│  │ Visited candidate's address on Jan 16, 2024.   │   │
│  │ Confirmed residential address matches records. │   │
│  │ Verified with utility bill and landlord.       │   │
│  └─────────────────────────────────────────────────┘   │
│                                                          │
│  Evidence (Optional):                                   │
│  [Upload Photo/Document]                                │
│                                                          │
│           [Cancel]              [Submit]                │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

#### API Call to Submit:
```javascript
POST /secure/updateInternalVerification
Content-Type: application/json

{
  "verificationId": "ver_123",
  "stage": "primary",
  "checkName": "address_verification",
  "status": "COMPLETED",
  "remarks": "Visited candidate's address on Jan 16, 2024. Confirmed residential address matches records. Verified with utility bill and landlord."
}
```

#### Response:
```json
{
  "check": "address_verification",
  "status": "COMPLETED",
  "stageCompleted": false,  // true if ALL checks in stage are done
  "canProceed": true
}
```

---

## 🔄 Complete UI Flow

### **Flow 1: HR Initiates Manual Verification**

```
Step 1: HR selects candidate
   ↓
Step 2: HR clicks "Start Manual Verification"
   ↓
Step 3: UI shows form to select checks
   ↓
Step 4: UI calls API:
   POST /secure/initiateStageVerification {
     "candidateId": "cand_456",
     "organizationId": "org_789",
     "stages": {
       "primary": [
         "address_verification",
         "education_check_manual",
         "supervisory_check"
       ]
     }
   }
   ↓
Step 5: API returns verificationId
   ↓
Step 6: UI redirects to verification detail page
```

### **Flow 2: Field Agent Completes Check**

```
Step 1: Agent opens verification list
   ↓
Step 2: Agent clicks on candidate
   ↓
Step 3: Agent sees pending checks
   ↓
Step 4: Agent clicks "Mark as Complete" on address_verification
   ↓
Step 5: Modal opens with form
   ↓
Step 6: Agent fills:
   - Status: COMPLETED
   - Remarks: "Visited site, confirmed address"
   - Upload: photo.jpg (optional)
   ↓
Step 7: Agent clicks Submit
   ↓
Step 8: UI calls API:
   POST /secure/updateInternalVerification {
     "verificationId": "ver_123",
     "stage": "primary",
     "checkName": "address_verification",
     "status": "COMPLETED",
     "remarks": "Visited site, confirmed address"
   }
   ↓
Step 9: API returns success
   ↓
Step 10: UI updates the check status to ✅ COMPLETED
   ↓
Step 11: UI updates progress bar (e.g., 33% → 66%)
```

---

## 📊 Real-Time Updates

### Option A: Polling (Simple)
```javascript
// Refresh verification status every 10 seconds
setInterval(() => {
  fetch(`/secure/getVerificationById/${verificationId}`)
    .then(res => res.json())
    .then(data => updateUI(data));
}, 10000);
```

### Option B: WebSocket (Advanced)
```javascript
// Real-time updates when other users complete checks
const ws = new WebSocket('ws://api.example.com/verification-updates');
ws.onmessage = (event) => {
  const update = JSON.parse(event.data);
  if (update.verificationId === currentVerificationId) {
    updateUI(update);
  }
};
```

---

## 🎨 UI Components Needed

### 1. **VerificationListCard**
```jsx
<VerificationCard
  candidateName="John Doe"
  stage="primary"
  status="IN_PROGRESS"
  completionPercentage={50}
  totalChecks={4}
  completedChecks={2}
  onViewDetails={() => navigate(`/verification/${verificationId}`)}
/>
```

### 2. **CheckItem**
```jsx
<CheckItem
  checkName="address_verification"
  status="PENDING"
  remarks={null}
  onMarkComplete={() => openModal(checkName)}
/>
```

### 3. **UpdateCheckModal**
```jsx
<UpdateCheckModal
  isOpen={isModalOpen}
  checkName="address_verification"
  verificationId="ver_123"
  stage="primary"
  onSubmit={handleSubmit}
  onClose={() => setIsModalOpen(false)}
/>
```

### 4. **ProgressBar**
```jsx
<ProgressBar
  percentage={50}
  completedChecks={2}
  totalChecks={4}
/>
```

---

## 📝 Required Form Validations

### Update Check Form:
```javascript
const validateForm = (data) => {
  const errors = {};
  
  // Status is required
  if (!data.status) {
    errors.status = "Status is required";
  }
  
  // Status must be valid
  if (!["COMPLETED", "FAILED", "IN_PROGRESS"].includes(data.status)) {
    errors.status = "Invalid status";
  }
  
  // Remarks required for COMPLETED or FAILED
  if ((data.status === "COMPLETED" || data.status === "FAILED") && !data.remarks) {
    errors.remarks = "Remarks are required when marking as completed or failed";
  }
  
  // Remarks minimum length
  if (data.remarks && data.remarks.length < 10) {
    errors.remarks = "Remarks must be at least 10 characters";
  }
  
  return errors;
};
```

---

## 🔐 Permissions & Access Control

### Who Can Update Checks?

The backend handles this, but UI should show/hide based on user role:

```javascript
const canUpdateCheck = (userRole, verification) => {
  // SUPER_ADMIN can update anything
  if (userRole === "SUPER_ADMIN") return true;
  
  // ORG_HR can update their org's verifications
  if (userRole === "ORG_HR" && verification.organizationId === user.organizationId) {
    return true;
  }
  
  // HELPER can only update verifications they initiated
  if (userRole === "HELPER" && verification.initiatedBy === user.email) {
    return true;
  }
  
  return false;
};
```

---

## 📱 Mobile Considerations

For field agents using mobile:

1. **Simplified UI** - Larger buttons, less clutter
2. **Camera Integration** - Quick photo upload for evidence
3. **Offline Support** - Save updates locally, sync when online
4. **GPS Tagging** - Auto-capture location for address verification

---

## 🎯 Summary: What UI Needs to Do

### **Minimum Required:**

1. ✅ **List Page** - Show all verifications with progress
2. ✅ **Detail Page** - Show all checks for a candidate
3. ✅ **Update Form** - Allow marking checks as complete with remarks
4. ✅ **Progress Display** - Show percentage and counts

### **API Calls Needed:**

1. `GET /secure/getVerificationsByOrganization` - List verifications
2. `GET /secure/getVerificationById/{id}` - Get details
3. `POST /secure/updateInternalVerification` - Update check status

### **Data to Send:**

```javascript
{
  verificationId: "ver_123",      // Required
  stage: "primary",               // Required
  checkName: "address_verification", // Required
  status: "COMPLETED",            // Required: COMPLETED | FAILED | IN_PROGRESS
  remarks: "Detailed notes..."    // Required for COMPLETED/FAILED
}
```

### **Data to Display:**

- Candidate name, email, phone
- Current stage
- Overall progress percentage
- List of all checks with status
- Remarks for completed checks
- Timestamp when completed

That's everything your UI team needs! 🎉
