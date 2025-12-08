# 🤖 AI CV Validation - Independent Feature

## **Overview**

AI CV Validation is now a **completely independent feature** - not part of primary/secondary/final stages, but stored in the same verification record and billed like other checks.

---

## **Key Changes**

### **1. Endpoint Input Changed**

**Before:**
```json
{
  "verificationId": "507f1f77bcf86cd799439011",
  "resume": <file>,
  "panNumber": "ABCDE1234F"
}
```

**After:**
```json
{
  "candidateId": "507f1f77bcf86cd799439012",  // ✅ Changed to candidateId
  "resume": <file>,
  "panNumber": "ABCDE1234F"
}
```

---

### **2. Storage Structure**

**Verification Document:**
```javascript
{
  "_id": ObjectId("..."),
  "candidateId": "507f...",
  "organizationId": "507f...",
  
  // Normal checks in stages
  "stages": {
    "primary": [
      {"check": "Employment Verification", "status": "COMPLETED"}
    ],
    "secondary": [
      {"check": "Education Verification", "status": "PENDING"}
    ],
    "final": []
  },
  
  // ✅ AI CV Validation - INDEPENDENT FIELD
  "aiCvValidation": {
    "status": "COMPLETED",
    "candidateType": "EXPERIENCED",
    "hasUan": true,
    "uanNumber": "123456789012",
    "authenticity_score": 85,
    "recommendation": "APPROVE",
    "analysis": {
      "candidate_profile": {...},
      "positive_findings": [...],
      "negative_findings": [...],
      "education_analysis": {...},
      "employment_analysis": {...},
      "timeline_analysis": {...},
      "red_flags": [...],
      "summary": "...",
      "method": "OpenAI-GPT4o-mini-Authenticity"
    },
    "completedAt": "2024-12-07T12:00:00Z",
    "completedBy": "admin@bgv.in",
    "validation_id": "uuid-here"
  },
  
  "overallStatus": "IN_PROGRESS"
}
```

---

## **API Usage**

### **Endpoint**

```
POST /secure/ai_cv_validation
```

### **Request (Form Data)**

```
candidateId: 507f1f77bcf86cd799439012
resume: <file> (optional - will use candidate.resumePath if not provided)
panNumber: ABCDE1234F (optional)
hasUan: yes/no (optional - manual override)
```

### **Response**

```json
{
  "message": "AI CV authenticity check completed successfully. Please review and submit.",
  "verificationId": "507f1f77bcf86cd799439011",
  "candidateName": "John Doe",
  "candidateType": "EXPERIENCED",
  "uanNumber": "123456789012",
  "hasUan": true,
  "uanVerificationNote": "UAN verified via EPFO API",
  "analysis": {
    "authenticity_score": 85,
    "recommendation": "APPROVE",
    "candidate_profile": {
      "name": "John Doe",
      "total_experience_years": 5,
      "education_level": "Bachelor's",
      "current_role": "Software Engineer"
    },
    "positive_findings": [
      "Consistent employment timeline",
      "Progressive career growth",
      "Verified UAN number"
    ],
    "negative_findings": [
      "Minor gap of 2 months between jobs"
    ],
    "education_analysis": {...},
    "employment_analysis": {...},
    "timeline_analysis": {...},
    "red_flags": [],
    "summary": "Overall authentic CV with minor gaps..."
  }
}
```

---

## **Billing Integration**

### **Organization Services Configuration**

Add to organization's services array:
```json
{
  "services": [
    {"serviceName": "Employment Verification", "price": 120.0},
    {"serviceName": "Education Verification", "price": 150.0},
    {"serviceName": "AI CV Validation", "price": 50.0}  // ✅ Add this
  ]
}
```

### **Invoice Generation**

**Batch Invoice will include:**
```json
{
  "items": [
    {
      "checkName": "Employment Verification",
      "stage": "primary",
      "price": 120.0,
      "completedAt": "2024-12-07T10:00:00Z"
    },
    {
      "checkName": "Education Verification",
      "stage": "secondary",
      "price": 150.0,
      "completedAt": "2024-12-07T11:00:00Z"
    },
    {
      "checkName": "AI CV Validation",
      "stage": "independent",  // ✅ Not part of primary/secondary/final
      "price": 50.0,
      "completedAt": "2024-12-07T12:00:00Z"
    }
  ],
  "subtotal": 320.0,
  "tax": 57.6,
  "grandTotal": 377.6
}
```

---

## **Workflow**

### **Option 1: AI CV Validation First (Auto-creates Verification)**

```
Step 1: Run AI CV Validation
POST /secure/ai_cv_validation
{
  "candidateId": "507f...",
  "resume": <file>
}
✅ If no verification record exists, it will be auto-created!

Step 2: Add Normal Checks Later (Optional)
POST /secure/initiateStageVerification
{
  "candidateId": "507f...",
  "organizationId": "507f...",
  "stages": {
    "primary": ["Employment Verification"]
  }
}

Step 3: Generate Invoice
POST /secure/generate_batch_invoice
{
  "organizationId": "507f...",
  "includeCompleted": true
}
```

### **Option 2: Normal Workflow (Verification Already Exists)**

```
Step 1: Create Verification
POST /secure/initiateStageVerification
{
  "candidateId": "507f...",
  "organizationId": "507f...",
  "stages": {
    "primary": ["Employment Verification", "Education Verification"]
  }
}

Step 2: Run Normal Checks
POST /secure/runStage
{
  "verificationId": "507f...",
  "stage": "primary"
}

Step 3: Run AI CV Validation (Independent)
POST /secure/ai_cv_validation
{
  "candidateId": "507f...",
  "resume": <file>
}

Step 4: Generate Invoice
POST /secure/generate_batch_invoice
{
  "organizationId": "507f...",
  "includeCompleted": true
}
```

**Result:** Invoice includes both stage checks AND AI CV validation!

---

## **Key Differences**

| Aspect | Normal Checks | AI CV Validation |
|--------|--------------|------------------|
| **Initiation** | `initiateStageVerification` | Direct endpoint |
| **Storage** | `verification.stages.primary/secondary/final` | `verification.aiCvValidation` |
| **Stage** | primary/secondary/final | independent |
| **Billing** | Included in invoice | ✅ Included in invoice |
| **Status** | Part of overallStatus | Own status field |
| **UI Section** | Stage-based | Separate section |

---

## **Testing**

### **1. Run AI CV Validation**

```bash
curl -X POST https://maihootech.in/secure/ai_cv_validation \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "candidateId=507f1f77bcf86cd799439012" \
  -F "resume=@resume.pdf" \
  -F "panNumber=ABCDE1234F"
```

### **2. Check Verification Record**

```javascript
db.verifications.findOne({"candidateId": "507f1f77bcf86cd799439012"})

// Should have:
{
  "stages": {...},  // Normal checks
  "aiCvValidation": {  // ✅ Independent field
    "status": "COMPLETED",
    "authenticity_score": 85,
    ...
  }
}
```

### **3. Generate Invoice**

```bash
curl -X POST https://maihootech.in/secure/generate_batch_invoice \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "organizationId": "507f1f77bcf86cd799439011",
    "includeCompleted": true
  }'
```

**Check:** Invoice should include "AI CV Validation" as a separate line item with `stage: "independent"`

---

## **Frontend Integration**

### **Separate UI Section**

```jsx
// Verification Details Page
<div>
  {/* Normal Stages */}
  <StagesSection>
    <Stage name="Primary" checks={verification.stages.primary} />
    <Stage name="Secondary" checks={verification.stages.secondary} />
    <Stage name="Final" checks={verification.stages.final} />
  </StagesSection>
  
  {/* AI CV Validation - Independent */}
  <AICVValidationSection>
    <h3>AI CV Validation (Independent Feature)</h3>
    {verification.aiCvValidation ? (
      <div>
        <p>Status: {verification.aiCvValidation.status}</p>
        <p>Score: {verification.aiCvValidation.authenticity_score}/100</p>
        <p>Recommendation: {verification.aiCvValidation.recommendation}</p>
        <button onClick={viewReport}>View Full Report</button>
      </div>
    ) : (
      <button onClick={runAICVValidation}>Run AI CV Validation</button>
    )}
  </AICVValidationSection>
</div>
```

---

## **Benefits**

✅ **Independent Feature** - Not tied to stage workflow  
✅ **Same Record** - No separate database/collection needed  
✅ **Automatic Billing** - Included in invoices like other checks  
✅ **Flexible** - Can be run anytime, not dependent on stage completion  
✅ **Clean Separation** - Doesn't clutter primary/secondary/final stages  
✅ **Easy to Track** - Clear field in verification document  
✅ **Auto-creates Verification** - If no verification exists, creates one automatically  

---

## **Summary**

AI CV Validation is now a **standalone feature** that:
- Takes `candidateId` instead of `verificationId`
- Stores results in `verification.aiCvValidation` field (NOT in stages)
- Gets billed automatically in invoices with `stage: "independent"`
- Works independently from primary/secondary/final stage workflow

**Ready to use! 🚀**
