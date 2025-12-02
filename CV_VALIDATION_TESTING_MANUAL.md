# AI CV Validation - Complete Testing Manual

## 📋 Overview

This guide shows how to test the AI CV Validation system that:
- ✅ Validates resume authenticity (no JD comparison)
- ✅ Detects gaps, overlaps, inconsistencies
- ✅ Determines candidate type (Fresher/Experienced)
- ✅ Calls UAN employment history API for experienced candidates
- ✅ Returns positive and negative findings
- ✅ Requires manual review for final decision

---

## 🔑 API Requirements

### Employment History API
```
Endpoint: https://kyc-api.surepass.io/api/v1/income/employment-history-uan-v2
Required: UAN Number only
Payload: {"id_number": "123456789012"}
```

### PAN to UAN API (Optional - if UAN not available)
```
Endpoint: https://kyc-api.surepass.io/api/v1/pan/pan-to-uan
Required: PAN Number only
Payload: {"pan_number": "ABCDE1234F"}
```

**Note:** You can get UAN from PAN if candidate doesn't know their UAN!

---

## 🚀 Complete Testing Flow

### Prerequisites
1. ✅ Backend server running
2. ✅ Valid authentication token
3. ✅ Candidate created
4. ✅ Verification initiated with `ai_cv_validation` check
5. ✅ Resume file (PDF/DOCX)

---

## 📝 STEP-BY-STEP TESTING

### STEP 0: Setup Environment Variables

```bash
# Postman Environment Variables
base_url = https://your-api-domain.com
auth_token = (from login)
organizationId = (from login)
candidateId = (from create candidate)
verificationId = (from initiate verification)
```

---

### STEP 1: Login

**Endpoint:**
```
POST {{base_url}}/auth/login
```

**Body:**
```json
{
  "email": "your-email@example.com",
  "password": "your-password"
}
```

**Response:**
```json
{
  "token": "eyJhbGc...",
  "organizationId": "org_123",
  "role": "SPOC"
}
```

**✅ Save:** `auth_token` and `organizationId`

---

### STEP 2: Create Candidate (with UAN for testing)

**Endpoint:**
```
POST {{base_url}}/secure/addCandidate
Authorization: Bearer {{auth_token}}
```

**Body (Experienced Candidate with UAN):**
```json
{
  "firstName": "Rajesh",
  "lastName": "Kumar",
  "email": "rajesh.kumar@example.com",
  "phone": "9876543210",
  "panNumber": "ABCDE1234F",
  "aadhaarNumber": "123456789012",
  "uanNumber": "101234567890",
  "address": "Plot 123, Hyderabad",
  "organizationId": "{{organizationId}}",
  "expectedDegree": "B.Tech",
  "expectedGraduationYear": "2018"
}
```

**Body (Fresher Candidate - No UAN):**
```json
{
  "firstName": "Priya",
  "lastName": "Sharma",
  "email": "priya.sharma@example.com",
  "phone": "9876543211",
  "panNumber": "FGHIJ5678K",
  "aadhaarNumber": "987654321098",
  "address": "Flat 456, Bangalore",
  "organizationId": "{{organizationId}}",
  "expectedDegree": "B.Tech",
  "expectedGraduationYear": "2023"
}
```

**Response:**
```json
{
  "candidateId": "cand_456",
  "message": "Candidate added successfully"
}
```

**✅ Save:** `candidateId`

---

### STEP 3: Initiate Verification with AI CV Check

**Endpoint:**
```
POST {{base_url}}/secure/initiateStageVerification
Authorization: Bearer {{auth_token}}
```

**Body:**
```json
{
  "candidateId": "{{candidateId}}",
  "organizationId": "{{organizationId}}",
  "stages": {
    "primary": ["ai_cv_validation"]
  }
}
```

**Response:**
```json
{
  "verificationId": "ver_789",
  "stages": {
    "primary": [
      {
        "check": "ai_cv_validation",
        "status": "PENDING"
      }
    ]
  }
}
```

**✅ Save:** `verificationId`

---

### STEP 4: Upload Resume (if not already uploaded)

**Endpoint:**
```
POST {{base_url}}/secure/candidate/uploadResume
Authorization: Bearer {{auth_token}}
Content-Type: multipart/form-data
```

**Form Data:**
```
candidateId: {{candidateId}}
resume: [Select Resume PDF/DOCX file]
```

**Response:**
```json
{
  "message": "Resume uploaded successfully",
  "path": "/mnt/resumes/cand_456.pdf"
}
```

---

### STEP 5: Run AI CV Validation

**Endpoint:**
```
POST {{base_url}}/secure/ai_cv_validation
Authorization: Bearer {{auth_token}}
Content-Type: application/x-www-form-urlencoded
```

**Form Data:**
```
verificationId: {{verificationId}}
panNumber: ABCDE1234F
```

**Important Notes:**
- ✅ Resume must be uploaded first (Step 4)
- ✅ System fetches resume from database automatically
- ❌ **NO resume file upload here** - it's already in DB
- ❌ **NO JD file required** (we're not comparing with JD)

**What Happens:**
1. System extracts text from resume
2. AI analyzes resume for:
   - Candidate type (Fresher/Experienced)
   - Employment gaps
   - Date overlaps
   - Education inconsistencies
   - Suspicious patterns
3. If experienced + has UAN:
   - Calls Surepass UAN API
   - Gets employment history
   - Cross-validates with resume
4. Generates report with positive/negative findings
5. Calculates authenticity score
6. Keeps status as PENDING for manual review

**Expected Response:**
```json
{
  "message": "AI CV analysis completed successfully. Please review and submit the check.",
  "verificationId": "ver_789",
  "candidateName": "Rajesh Kumar",
  "analysis": {
    "overall_score": 75,
    "candidate_type": "EXPERIENCED_WITH_UAN",
    "hiring_recommendation": "APPROVE_WITH_CLARIFICATIONS",
    
    "positive_findings": [
      {
        "category": "EDUCATION",
        "finding": "Degree from recognized university",
        "score_contribution": 10
      },
      {
        "category": "UAN_VALIDATION",
        "finding": "All companies verified in UAN records",
        "score_contribution": 15
      },
      {
        "category": "CONSISTENCY",
        "finding": "No date overlaps detected",
        "score_contribution": 10
      }
    ],
    
    "negative_findings": [
      {
        "category": "EMPLOYMENT_GAP",
        "finding": "6-month gap between jobs",
        "period": "Jan 2020 - Jun 2020",
        "severity": "MEDIUM",
        "score_impact": -10,
        "requires_explanation": true
      },
      {
        "category": "UAN_MISMATCH",
        "finding": "Company name variation",
        "details": "Resume: 'ABC Technologies' vs UAN: 'ABC Tech'",
        "severity": "LOW",
        "score_impact": -5
      }
    ],
    
    "uan_validation": {
      "status": "COMPLETED",
      "uan_number": "101234567890",
      "records_found": 3,
      "match_percentage": 85,
      "employment_history": [
        {
          "company": "ABC Tech Solutions",
          "period": "2021-2023",
          "status": "VERIFIED"
        },
        {
          "company": "XYZ Corp",
          "period": "2019-2021",
          "status": "VERIFIED"
        }
      ]
    },
    
    "recommendations": [
      "Request explanation for 6-month employment gap",
      "Verify company name variation with candidate",
      "Overall profile appears authentic"
    ]
  }
}
```

**📊 Progress:** AI analysis complete, awaiting manual review

---

### STEP 6: Get AI Validation Results

**Endpoint:**
```
GET {{base_url}}/secure/ai_cv_validation_results/{{verificationId}}
Authorization: Bearer {{auth_token}}
```

**Response:**
```json
{
  "verificationId": "ver_789",
  "candidateName": "Rajesh Kumar",
  "candidateEmail": "rajesh.kumar@example.com",
  "aiAnalysis": {
    "overall_score": 75,
    "candidate_type": "EXPERIENCED_WITH_UAN",
    "total_experience_years": 5.5,
    "authenticity_score": 75,
    "recommendation": "APPROVE_WITH_CLARIFICATIONS",
    
    "positive_findings": [...],
    "negative_findings": [...],
    
    "uan_validation": {
      "status": "COMPLETED",
      "uan_number": "101234567890",
      "records_found": 3,
      "match_percentage": 85,
      "discrepancies": [
        {
          "type": "COMPANY_NAME_VARIATION",
          "severity": "LOW"
        }
      ]
    },
    
    "detailed_analysis": {
      "employment_timeline": {
        "total_companies": 3,
        "total_duration": "5 years 6 months",
        "gaps_detected": 1,
        "overlaps_detected": 0,
        "average_tenure": "1.8 years"
      },
      "education_analysis": {
        "highest_degree": "B.Tech",
        "institution": "JNTU Hyderabad",
        "graduation_year": 2018,
        "consistency_check": "PASSED"
      }
    },
    
    "risk_assessment": {
      "overall_risk": "LOW",
      "red_flags": 0,
      "yellow_flags": 1,
      "green_flags": 4
    }
  }
}
```

---

### STEP 7: Manual Review & Submit Decision

**Endpoint:**
```
POST {{base_url}}/secure/submit_ai_cv_validation
Authorization: Bearer {{auth_token}}
Content-Type: multipart/form-data
```

**Form Data (Approve):**
```
verificationId: {{verificationId}}
final_status: COMPLETED
staff_remarks: Reviewed AI analysis. Employment gap explained during interview. Candidate confirmed company name variation. Approved.
```

**Form Data (Reject):**
```
verificationId: {{verificationId}}
final_status: FAILED
staff_remarks: Multiple red flags detected. UAN records don't match resume. Candidate unable to explain discrepancies. Rejected.
```

**Response:**
```json
{
  "message": "AI CV validation check submitted successfully",
  "verificationId": "ver_789",
  "final_status": "COMPLETED",
  "candidateName": "Rajesh Kumar"
}
```

**📊 Progress:** 100% complete!

---

## 🧪 Test Scenarios

### Scenario 1: Experienced Candidate with UAN

**Candidate Data:**
```json
{
  "firstName": "Amit",
  "lastName": "Patel",
  "uanNumber": "101234567890",
  "panNumber": "ABCDE1234F",
  "expectedGraduationYear": "2015"
}
```

**Expected Result:**
- ✅ Candidate type: EXPERIENCED_WITH_UAN
- ✅ UAN API called automatically
- ✅ Employment history cross-validated
- ✅ Gaps/overlaps detected
- ✅ Authenticity score calculated

---

### Scenario 2: Fresher Candidate (No UAN)

**Candidate Data:**
```json
{
  "firstName": "Sneha",
  "lastName": "Reddy",
  "expectedGraduationYear": "2023"
}
```

**Expected Result:**
- ✅ Candidate type: FRESHER
- ✅ UAN API NOT called
- ✅ Focus on education validation
- ✅ Internship verification
- ✅ Skills assessment

---

### Scenario 3: Experienced without UAN

**Candidate Data:**
```json
{
  "firstName": "Vikram",
  "lastName": "Singh",
  "expectedGraduationYear": "2017"
}
```

**Resume shows:** 4 years experience but no UAN

**Expected Result:**
- ✅ Candidate type: EXPERIENCED_NO_UAN
- ✅ UAN API NOT called
- ✅ Pattern-based validation
- ✅ Timeline consistency check
- ✅ Recommendation for manual verification

---

### Scenario 4: Get UAN from PAN

**If candidate has PAN but no UAN:**

**Step 1: Call PAN to UAN API**
```bash
# This happens automatically in the system
POST https://kyc-api.surepass.io/api/v1/pan/pan-to-uan
{
  "pan_number": "ABCDE1234F"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "uan": "101234567890",
    "name": "AMIT PATEL"
  }
}
```

**Step 2: Use UAN for employment history**
```bash
POST https://kyc-api.surepass.io/api/v1/income/employment-history-uan-v2
{
  "id_number": "101234567890"
}
```

---

## 📊 Understanding the Response

### Authenticity Score Breakdown

**Score Range:**
- **90-100**: Highly Authentic ✅
- **75-89**: Authentic with minor issues ⚠️
- **60-74**: Requires manual review 🔍
- **40-59**: Suspicious 🚨
- **0-39**: High risk ❌

**Score Calculation:**
```
Base Score: 100

Positive Contributions:
+ All UAN records match: +15
+ No employment gaps: +10
+ Recognized institution: +10
+ Complete information: +5
+ Consistent timeline: +10

Negative Deductions:
- Employment gap (>3 months): -10 per gap
- Date overlap: -25 per overlap
- UAN mismatch (major): -20
- UAN mismatch (minor): -5
- Missing employment in UAN: -15
- Education inconsistency: -20
- Suspicious pattern: -10 to -25

Final Score = Base + Positive - Negative
```

---

## 🔍 What Gets Validated

### For All Candidates:
1. ✅ Education timeline consistency
2. ✅ Age vs graduation year match
3. ✅ Employment date consistency
4. ✅ Gap detection (>3 months)
5. ✅ Overlap detection
6. ✅ Suspicious patterns
7. ✅ Missing information
8. ✅ Template language detection

### Additional for Experienced with UAN:
9. ✅ UAN employment history match
10. ✅ Company name verification
11. ✅ Employment period validation
12. ✅ Designation consistency
13. ✅ Missing companies in UAN

---

## 🎯 API Data Requirements

### Minimum Required in Candidate:
```json
{
  "firstName": "Required",
  "lastName": "Required",
  "email": "Required",
  "phone": "Required",
  "organizationId": "Required"
}
```

### Optional but Recommended:
```json
{
  "panNumber": "For PAN to UAN conversion",
  "uanNumber": "For direct UAN validation",
  "aadhaarNumber": "For additional verification",
  "expectedDegree": "For education validation",
  "expectedGraduationYear": "For timeline validation"
}
```

### For UAN Employment History API:
```
✅ ONLY UAN number required
❌ No other candidate data needed
```

---

## 🐛 Troubleshooting

### Issue 1: "UAN not found"

**Cause:** Invalid UAN or not registered with EPFO

**Solution:**
- Try PAN to UAN conversion
- Mark as "EXPERIENCED_NO_UAN"
- Proceed with pattern-based validation

---

### Issue 2: "No employment history found"

**Cause:** 
- Candidate worked in unorganized sector
- Freelancer/Consultant
- Foreign company

**Solution:**
- System automatically marks as "EXPERIENCED_NO_UAN"
- Validates based on resume patterns only
- Recommends manual verification

---

### Issue 3: "Low authenticity score"

**Cause:** Multiple red flags detected

**Action:**
- Review negative findings
- Check UAN discrepancies
- Verify with candidate
- Make manual decision

---

## 📝 Postman Collection Structure

```
AI CV Validation Testing
├── 1. Authentication
│   └── Login
├── 2. Candidate Setup
│   ├── Create Experienced Candidate (with UAN)
│   ├── Create Fresher Candidate
│   └── Create Experienced Candidate (no UAN)
├── 3. Verification Setup
│   └── Initiate Verification with AI CV Check
├── 4. Resume Upload
│   └── Upload Resume to Candidate
├── 5. AI CV Validation
│   ├── Run AI Analysis (with PAN)
│   ├── Get AI Validation Results
│   └── Submit Final Decision
└── 6. Direct API Tests (Optional)
    ├── Test PAN to UAN API
    └── Test Employment History API
```

---

## ✅ Testing Checklist

- [ ] Login successful, token saved
- [ ] Candidate created with UAN
- [ ] Verification initiated with ai_cv_validation check
- [ ] Resume uploaded to candidate record
- [ ] AI validation called with verificationId + PAN
- [ ] AI analysis completed
- [ ] Candidate type detected correctly
- [ ] UAN API called (if applicable)
- [ ] Positive findings returned
- [ ] Negative findings returned
- [ ] Authenticity score calculated
- [ ] Manual review completed
- [ ] Final decision submitted
- [ ] Check marked as COMPLETED/FAILED

---

## 🎉 Success Criteria

✅ System detects candidate type automatically
✅ UAN API called only for experienced candidates
✅ Employment history cross-validated
✅ Gaps and overlaps detected
✅ Positive and negative findings clear
✅ Authenticity score makes sense
✅ Manual review works smoothly
✅ Final decision recorded

---

That's your complete testing manual! 🚀

**Key Points:**
- ✅ Only UAN number needed for employment API
- ✅ Can get UAN from PAN if needed
- ✅ No JD required (authenticity check only)
- ✅ System handles all candidate types
- ✅ Manual review always required
