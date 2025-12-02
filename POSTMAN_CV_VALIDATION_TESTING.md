# Postman Testing Guide - AI CV Authenticity Validation

## Complete Flow from Start to Finish

### Prerequisites
- Candidate must have resume uploaded in database
- Candidate must have PAN number
- Verification record must exist with `ai_cv_validation` check

---

## STEP 1: Initiate Stage Verification

**Endpoint:** `POST /secure/initiateStageVerification`

**Purpose:** Creates verification record with all checks including `ai_cv_validation`

**Request:**
```
POST {{base_url}}/secure/initiateStageVerification
Authorization: Bearer {{auth_token}}
Content-Type: application/json

{
  "candidateId": "674a1234567890abcdef1234",
  "organizationId": "674a9876543210fedcba9876",
  "stages": {
    "primary": [
      "pan_verification",
      "ai_cv_validation"
    ]
  }
}
```

**Response:**
```json
{
  "message": "Verification initiated successfully",
  "verificationId": "674b1111222233334444aaaa",
  "candidateId": "674a1234567890abcdef1234",
  "stages": {
    "primary": [
      {
        "check": "pan_verification",
        "status": "PENDING"
      },
      {
        "check": "ai_cv_validation",
        "status": "PENDING",
        "aiAnalysisCompleted": false
      }
    ]
  }
}
```

**Save:** `verificationId` for next steps

---

## STEP 2: Run AI CV Authenticity Validation

**Endpoint:** `POST /secure/ai_cv_validation`

**Purpose:** Runs AI authenticity check on candidate's CV

**Option A: With UAN Number (Recommended - Fastest)**
```
POST {{base_url}}/secure/ai_cv_validation
Authorization: Bearer {{auth_token}}
Content-Type: multipart/form-data

verificationId: 674b1111222233334444aaaa
uanNumber: 101848108802
resume: [Select PDF/DOCX file]
```
**Note:** Provide UAN directly to skip PAN-to-UAN API call (saves 1 API call)

**Option B: With PAN Number (Auto-fetches UAN)**
```
POST {{base_url}}/secure/ai_cv_validation
Authorization: Bearer {{auth_token}}
Content-Type: multipart/form-data

verificationId: 674b1111222233334444aaaa
panNumber: ABCDE1234F
resume: [Select PDF/DOCX file]
```
**Note:** System will call PAN-to-UAN API first, then fetch employment history

**Option C: Without UAN/PAN (CV Analysis Only)**
```
POST {{base_url}}/secure/ai_cv_validation
Authorization: Bearer {{auth_token}}
Content-Type: multipart/form-data

verificationId: 674b1111222233334444aaaa
resume: [Select PDF/DOCX file]
```
**Note:** No employment verification, analysis based on CV content only

**What Happens:**
1. System fetches candidate resume from database
2. Extracts text from resume (PDF/DOCX)
3. Calls PAN-to-UAN API to get UAN number
4. If UAN found → Fetches employment history from Surepass
5. Determines candidate type:
   - `FRESHER` - No UAN, no experience
   - `EXPERIENCED` - UAN found with employment history
   - `EXPERIENCED_NO_UAN` - Claims experience but no UAN
6. Runs AI authenticity validation with employment context
7. Stores results with status still `PENDING`
8. Sets `aiAnalysisCompleted: true`

**Response:**
```json
{
  "message": "AI CV authenticity check completed successfully. Please review and submit.",
  "verificationId": "674b1111222233334444aaaa",
  "candidateName": "John Doe",
  "candidateType": "EXPERIENCED",
  "uanNumber": "123456789012",
  "employmentHistoryFetched": true,
  "analysis": {
    "authenticity_score": 85,
    "recommendation": "APPROVE",
    "candidate_profile": {
      "total_experience_years": 5,
      "education_level": "Bachelor's",
      "career_progression": "CONSISTENT",
      "timeline_clarity": "CLEAR"
    },
    "positive_findings": [
      "Clear timeline with no gaps",
      "Employment verified through UAN records",
      "Consistent career progression from junior to senior roles",
      "Education timeline does not overlap with employment",
      "Professional presentation and formatting"
    ],
    "negative_findings": [
      "Minor gap of 2 months between Company A and Company B"
    ],
    "education_analysis": {
      "education_entries": [
        "Bachelor of Technology, XYZ University, 2014-2018"
      ],
      "overlaps_detected": false,
      "overlap_details": [],
      "education_score": 95
    },
    "employment_analysis": {
      "employment_entries": [
        "ABC Tech Solutions, Senior Software Engineer, 2020-Present",
        "XYZ Corp, Software Engineer, 2018-2020"
      ],
      "gaps_detected": true,
      "gap_details": [
        "2-month gap between XYZ Corp and ABC Tech Solutions"
      ],
      "uan_verification_status": "MATCHED",
      "uan_discrepancies": [],
      "employment_score": 85
    },
    "timeline_analysis": {
      "timeline_consistent": true,
      "timeline_issues": [],
      "timeline_score": 90
    },
    "red_flags": [
      {
        "severity": "LOW",
        "category": "Employment Gap",
        "description": "2-month gap between jobs - likely normal job transition period"
      }
    ],
    "summary": "CV appears authentic with verified employment history through UAN. Minor gap detected but within acceptable range."
  }
}
```

**Note:** Check status is still `PENDING` - requires manual review and submission

---

## STEP 3: Get AI Validation Results (Optional Review)

**Endpoint:** `GET /secure/ai_cv_validation_results/{verificationId}`

**Purpose:** Review AI analysis results before submitting

**Request:**
```
GET {{base_url}}/secure/ai_cv_validation_results/674b1111222233334444aaaa
Authorization: Bearer {{auth_token}}
```

**Response:**
```json
{
  "verificationId": "674b1111222233334444aaaa",
  "candidateName": "John Doe",
  "candidateEmail": "john@example.com",
  "candidateType": "EXPERIENCED",
  "uanNumber": "123456789012",
  "employmentHistoryFetched": true,
  "aiAnalysis": {
    "authenticity_score": 85,
    "recommendation": "APPROVE",
    "positive_findings": [...],
    "negative_findings": [...],
    "education_analysis": {...},
    "employment_analysis": {...},
    "timeline_analysis": {...},
    "red_flags": [...]
  },
  "status": "PENDING",
  "remarks": "AI authenticity check completed. Score: 85/100. Type: EXPERIENCED. Recommendation: APPROVE. Awaiting manual review."
}
```

---

## STEP 4: Submit Final Decision

**Endpoint:** `POST /secure/submit_ai_cv_validation`

**Purpose:** Submit final decision after reviewing AI results

**Request (APPROVE):**
```
POST {{base_url}}/secure/submit_ai_cv_validation
Authorization: Bearer {{auth_token}}
Content-Type: application/x-www-form-urlencoded

verificationId=674b1111222233334444aaaa
final_status=COMPLETED
staff_remarks=Reviewed AI analysis. Employment verified through UAN. Approved.
```

**Request (REJECT):**
```
POST {{base_url}}/secure/submit_ai_cv_validation
Authorization: Bearer {{auth_token}}
Content-Type: application/x-www-form-urlencoded

verificationId=674b1111222233334444aaaa
final_status=FAILED
staff_remarks=Multiple red flags detected. Education-employment overlap found. Rejected.
```

**Response:**
```json
{
  "message": "AI CV authenticity validation submitted as COMPLETED successfully",
  "verificationId": "674b1111222233334444aaaa",
  "candidateName": "John Doe",
  "finalStatus": "COMPLETED",
  "staffRemarks": "Reviewed AI analysis. Employment verified through UAN. Approved."
}
```

**What Happens:**
- Check status changes from `PENDING` to `COMPLETED` or `FAILED`
- Staff remarks are saved
- Activity log is created

---

## Test Scenarios

### Scenario 1: Experienced Candidate with UAN (Clean CV)

**Input:**
```
verificationId: 674b1111222233334444aaaa
panNumber: ABCDE1234F (valid PAN with UAN)
```

**Expected Output:**
- candidateType: `EXPERIENCED`
- uanNumber: `123456789012`
- employmentHistoryFetched: `true`
- authenticity_score: `85-95`
- uan_verification_status: `MATCHED`
- recommendation: `APPROVE`
- Few or no red flags

---

### Scenario 2: Fresher Candidate (No UAN)

**Input:**
```
verificationId: 674b2222333344445555bbbb
panNumber: XYZAB5678C (valid PAN, no UAN)
```

**Expected Output:**
- candidateType: `FRESHER`
- uanNumber: `null`
- employmentHistoryFetched: `false`
- authenticity_score: `80-95`
- uan_verification_status: `NOT_AVAILABLE`
- recommendation: `APPROVE` or `REVIEW_REQUIRED`
- Focus on education timeline

---

### Scenario 3: Experienced without UAN

**Input:**
```
verificationId: 674b3333444455556666cccc
panNumber: PQRST9012D (valid PAN, no UAN but CV shows experience)
```

**Expected Output:**
- candidateType: `EXPERIENCED_NO_UAN`
- uanNumber: `null`
- employmentHistoryFetched: `false`
- authenticity_score: `60-80` (lower due to no verification)
- uan_verification_status: `NOT_AVAILABLE`
- recommendation: `REVIEW_REQUIRED`
- May have red flags about unverified employment

---

### Scenario 4: Education-Employment Overlap (Red Flag)

**Input:**
```
verificationId: 674b4444555566667777dddd
panNumber: LMNOP3456G
CV contains: Full-time MBA (2021-2023) while working full-time
```

**Expected Output:**
- authenticity_score: `30-50` (low)
- overlaps_detected: `true`
- overlap_details: ["Full-time MBA during full-time employment at Company X"]
- red_flags: [{ severity: "HIGH", category: "Education Overlap", ... }]
- recommendation: `REJECT` or `REVIEW_REQUIRED`

---

## Important Notes

### ⚠️ Cannot Submit Without AI Analysis

**This will FAIL:**
```
POST /secure/submit_ai_cv_validation
verificationId=674b1111222233334444aaaa
final_status=COMPLETED
```

**Error Response:**
```json
{
  "detail": "AI analysis must be completed before submission"
}
```

**You MUST run Step 2 first** to set `aiAnalysisCompleted: true`

---

### ✅ Correct Flow

```
1. POST /secure/initiateStageVerification
   ↓ (creates verification with ai_cv_validation check)
   
2. POST /secure/ai_cv_validation (with resume file)
   ↓ (runs AI analysis, sets aiAnalysisCompleted: true)
   
3. GET /secure/ai_cv_validation_results/{id}
   ↓ (optional - review results)
   
4. POST /secure/submit_ai_cv_validation
   ↓ (submits final decision)
   
✅ Check status: PENDING → COMPLETED/FAILED
```

---

## Postman Collection Variables

```
base_url: http://localhost:8000
auth_token: <your_jwt_token>
verificationId: 674b1111222233334444aaaa
panNumber: ABCDE1234F
```

---

## Error Handling

### Error 1: Resume Not Found
```json
{
  "detail": "Candidate resume not found. Please upload resume first."
}
```
**Solution:** Upload resume to candidate record first

### Error 2: Invalid PAN
```json
{
  "detail": "Could not fetch UAN from PAN"
}
```
**Solution:** System continues with EXPERIENCED_NO_UAN or FRESHER type

### Error 3: OpenAI Not Configured
```json
{
  "detail": "AI validation failed: OpenAI client not configured"
}
```
**Solution:** Set OPENAI_API_KEY in .env file

### Error 4: Cannot Submit Without AI Analysis
```json
{
  "detail": "AI analysis must be completed before submission"
}
```
**Solution:** Run POST /secure/ai_cv_validation first

---

## Summary

| Step | Endpoint | Purpose | Status Change |
|------|----------|---------|---------------|
| 1 | POST /secure/initiateStageVerification | Create verification | - → PENDING |
| 2 | POST /secure/ai_cv_validation | Run AI analysis (with resume) | PENDING (no change) |
| 3 | GET /secure/ai_cv_validation_results/{id} | Review results | No change |
| 4 | POST /secure/submit_ai_cv_validation | Submit decision | PENDING → COMPLETED/FAILED |

**Key Point:** AI analysis is MANDATORY before submission. You cannot skip Step 2 and directly submit.
