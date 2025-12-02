# AI CV Validation - Quick Test Guide

## ✅ Simplest Way to Test

### Step 1: Initiate Verification
```bash
POST /secure/initiateStageVerification
Content-Type: application/json

{
  "candidateId": "YOUR_CANDIDATE_ID",
  "organizationId": "YOUR_ORG_ID",
  "stages": {
    "primary": ["ai_cv_validation"]
  }
}
```

### Step 2: Run AI Validation (with resume file)
```bash
POST /secure/ai_cv_validation
Content-Type: multipart/form-data

verificationId: [from step 1]
panNumber: ABCDE1234F
resume: [Select PDF/DOCX file]
```

### Step 3: Submit Decision
```bash
POST /secure/submit_ai_cv_validation
Content-Type: application/x-www-form-urlencoded

verificationId=[from step 1]
final_status=COMPLETED
staff_remarks=Approved after review
```

## 📝 Key Points

✅ **Resume can be uploaded directly** in Step 2 (no separate upload needed)
✅ **OR** use resume from database if already uploaded
✅ **PAN number** is used to fetch UAN and employment history
✅ **No JD required** - pure authenticity check
✅ **Status stays PENDING** until you submit in Step 3

## 🎯 What You Get

```json
{
  "authenticity_score": 85,
  "candidate_type": "EXPERIENCED",
  "uan_number": "123456789012",
  "positive_findings": [
    "Employment verified through UAN",
    "Clear timeline with no gaps"
  ],
  "negative_findings": [
    "Minor gap between jobs (2 months)"
  ],
  "red_flags": [],
  "recommendation": "APPROVE"
}
```

## 🔧 Postman Setup

**Form Data Fields:**
- `verificationId` → Text
- `panNumber` → Text  
- `resume` → File (PDF/DOCX)

**Headers:**
- `Authorization: Bearer YOUR_TOKEN`
- `Content-Type: multipart/form-data` (auto-set by Postman)

Done! 🚀
