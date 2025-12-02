# Quick CV Validation Reference

## 🚀 Quick Start

### Step 1: Run AI Validation (with resume file)
```bash
POST /secure/ai_cv_validation
Content-Type: multipart/form-data

verificationId=674a1234567890abcdef1234
panNumber=ABCDE1234F
resume=[PDF/DOCX file]
```

**OR** (if resume already in database):
```bash
POST /secure/ai_cv_validation
Content-Type: application/x-www-form-urlencoded

verificationId=674a1234567890abcdef1234
panNumber=ABCDE1234F
```

### Step 2: Check Results
```bash
GET /secure/ai_cv_validation_results/674a1234567890abcdef1234
```

### Step 3: Submit Decision
```bash
POST /secure/submit_ai_cv_validation
Content-Type: application/x-www-form-urlencoded

verificationId=674a1234567890abcdef1234
final_status=COMPLETED
staff_remarks=Verified manually
```

## 📊 What You Get

### Candidate Types
- **FRESHER**: No work experience, no UAN
- **EXPERIENCED**: Has UAN with employment history
- **EXPERIENCED_NO_UAN**: Claims experience but no UAN found

### Analysis Output
```json
{
  "authenticity_score": 85,
  "positive_findings": [
    "Clear timeline with no gaps",
    "Employment verified through UAN",
    "Consistent career progression"
  ],
  "negative_findings": [
    "Minor gap between jobs (2 months)",
    "One company could not be verified"
  ],
  "red_flags": [
    {
      "severity": "MEDIUM",
      "category": "Employment Gap",
      "description": "2-month gap between Company A and Company B"
    }
  ],
  "recommendation": "APPROVE"
}
```

## 🎯 Key Features

### ✅ What It Does
- Checks CV authenticity (NO JD needed)
- Detects education-employment overlaps
- Identifies timeline gaps and inconsistencies
- Cross-verifies with UAN employment history
- Categorizes red flags by severity
- Returns positive AND negative findings
- Provides authenticity score (0-100)

### ❌ What It Doesn't Do
- Compare CV with Job Description
- Match skills to job requirements
- Provide hiring recommendations based on JD fit
- Require file uploads (uses DB resume)

## 🔍 Red Flag Severity

### HIGH
- Education-employment overlap (full-time study + full-time work)
- Major employment gaps (>6 months)
- UAN employment mismatch
- Fabricated companies

### MEDIUM
- Minor timeline inconsistencies
- Vague job descriptions
- Missing dates
- Unrealistic achievements

### LOW
- Formatting issues
- Minor gaps (<3 months)
- Incomplete contact info

## 📈 Scoring Guide

| Score | Meaning | Action |
|-------|---------|--------|
| 90-100 | Highly authentic, verified | APPROVE |
| 70-89 | Mostly authentic, minor concerns | APPROVE with notes |
| 50-69 | Moderate concerns | REVIEW_REQUIRED |
| 0-49 | Significant red flags | REJECT or deep investigation |

## 🔧 Prerequisites

1. **Resume file** (PDF/DOCX) - can be uploaded directly in the API call
2. **PAN number** required to fetch UAN
3. **OpenAI API key** configured in environment
4. **Surepass API token** configured for UAN lookup

## 🐛 Troubleshooting

### Error: "Candidate resume not found"
→ Upload resume to candidate record first

### Error: "Could not extract meaningful text"
→ Resume file may be corrupted or empty

### Error: "OpenAI client not configured"
→ Set OPENAI_API_KEY in .env file

### UAN not found
→ System will mark as EXPERIENCED_NO_UAN and continue validation

## 📝 Files Changed

1. **utils/ai_utils.py** - New authenticity validation function
2. **main.py** - Updated 3 endpoints
3. **apis.py** - No changes (already had UAN functions)

## 🎓 Example Scenarios

### Scenario 1: Clean CV
```
Input: Experienced candidate with UAN
Output: 
- Score: 92
- Type: EXPERIENCED
- Positive: 5 findings
- Negative: 0 findings
- Recommendation: APPROVE
```

### Scenario 2: Education Overlap Detected
```
Input: Candidate with full-time MBA during full-time job
Output:
- Score: 45
- Type: EXPERIENCED
- Positive: 2 findings
- Negative: 3 findings
- Red Flag: HIGH - Education-employment overlap
- Recommendation: REJECT
```

### Scenario 3: Fresher
```
Input: Fresh graduate, no work experience
Output:
- Score: 88
- Type: FRESHER
- Positive: 3 findings (education, projects)
- Negative: 0 findings
- Recommendation: APPROVE
```

## 🔗 Related Docs

- Full Guide: `AI_CV_AUTHENTICITY_VALIDATION_GUIDE.md`
- Changes Summary: `CV_VALIDATION_CHANGES_SUMMARY.md`
