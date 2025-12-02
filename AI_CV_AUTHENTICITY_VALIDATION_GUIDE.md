# AI CV Authenticity Validation System

## Overview
This system validates CV/Resume authenticity WITHOUT requiring a Job Description. It checks for:
- Education-employment overlaps
- Timeline inconsistencies
- Employment gaps
- Red flags and suspicious patterns
- Cross-verification with UAN employment history

## Key Features

### 1. **No JD Required**
- Only CV/Resume is analyzed
- Focus on authenticity, not job matching
- Checks for abnormalities and inconsistencies

### 2. **Candidate Type Detection**
The system automatically determines:
- **FRESHER**: No work experience
- **EXPERIENCED**: Has UAN number with employment history
- **EXPERIENCED_NO_UAN**: Claims experience but no UAN found

### 3. **UAN Employment History Integration**
- Fetches UAN from PAN number
- Retrieves employment history from Surepass API
- Cross-verifies CV claims with official records
- Identifies discrepancies

### 4. **AI Analysis Output**
Returns:
- **Positive Findings**: Valid points, strengths
- **Negative Findings**: Red flags, inconsistencies
- **Authenticity Score**: 0-100
- **Education Analysis**: Overlaps, timeline issues
- **Employment Analysis**: Gaps, UAN verification
- **Timeline Analysis**: Consistency check
- **Red Flags**: Categorized by severity (HIGH/MEDIUM/LOW)
- **Recommendation**: APPROVE / REVIEW_REQUIRED / REJECT

## API Endpoints

### 1. POST /secure/ai_cv_validation
**Purpose**: Run AI authenticity check on candidate's CV

**Parameters**:
```
verificationId: string (required) - Verification record ID
panNumber: string (required) - Candidate's PAN number
```

**Headers**:
```
Authorization: Bearer <token>
Content-Type: application/x-www-form-urlencoded
```

**Process**:
1. Fetches candidate record and resume
2. Extracts text from resume (PDF/DOCX)
3. Calls PAN-to-UAN API to get UAN number
4. If UAN found, fetches employment history
5. Determines candidate type (FRESHER/EXPERIENCED/EXPERIENCED_NO_UAN)
6. Runs AI authenticity validation with employment history context
7. Stores results with PENDING status for manual review

**Response**:
```json
{
  "message": "AI CV authenticity check completed successfully",
  "verificationId": "674a1234567890abcdef1234",
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
      "Consistent career progression",
      "Employment verified through UAN"
    ],
    "negative_findings": [
      "Minor gap between jobs (2 months)"
    ],
    "education_analysis": {
      "overlaps_detected": false,
      "education_score": 90
    },
    "employment_analysis": {
      "gaps_detected": false,
      "uan_verification_status": "MATCHED",
      "employment_score": 85
    },
    "red_flags": [],
    "summary": "CV appears authentic with verified employment history"
  }
}
```

### 2. GET /secure/ai_cv_validation_results/{verificationId}
**Purpose**: Retrieve AI authenticity check results

**Response**:
```json
{
  "verificationId": "674a1234567890abcdef1234",
  "candidateName": "John Doe",
  "candidateEmail": "john@example.com",
  "candidateType": "EXPERIENCED",
  "uanNumber": "123456789012",
  "employmentHistoryFetched": true,
  "aiAnalysis": { /* full analysis object */ },
  "status": "PENDING",
  "remarks": "AI authenticity check completed. Score: 85/100..."
}
```

### 3. POST /secure/submit_ai_cv_validation
**Purpose**: Submit final decision after manual review

**Parameters**:
```
verificationId: string (required)
final_status: string (required) - "COMPLETED" or "FAILED"
staff_remarks: string (optional) - Additional staff comments
```

**Response**:
```json
{
  "message": "AI CV authenticity validation submitted as COMPLETED successfully",
  "verificationId": "674a1234567890abcdef1234",
  "candidateName": "John Doe",
  "finalStatus": "COMPLETED",
  "staffRemarks": "Verified all details manually"
}
```

## Testing Guide

### Test Case 1: Experienced Candidate with UAN
```bash
POST /secure/ai_cv_validation
{
  "verificationId": "674a1234567890abcdef1234",
  "panNumber": "ABCDE1234F"
}
```
**Expected**: 
- Candidate type: EXPERIENCED
- UAN fetched successfully
- Employment history cross-verified
- High authenticity score if CV matches UAN data

### Test Case 2: Fresher Candidate
```bash
POST /secure/ai_cv_validation
{
  "verificationId": "674a1234567890abcdef1234",
  "panNumber": "XYZAB5678C"
}
```
**Expected**:
- Candidate type: FRESHER
- No UAN found
- Analysis focuses on education timeline
- Checks for realistic fresher profile

### Test Case 3: Experienced without UAN
```bash
POST /secure/ai_cv_validation
{
  "verificationId": "674a1234567890abcdef1234",
  "panNumber": "PQRST9012D"
}
```
**Expected**:
- Candidate type: EXPERIENCED_NO_UAN
- CV claims experience but no UAN
- Higher scrutiny on employment claims
- May flag for manual verification

## Workflow

```
1. Staff calls /secure/ai_cv_validation with verificationId and PAN
   ↓
2. System fetches candidate resume from database
   ↓
3. System extracts text from resume
   ↓
4. System calls PAN-to-UAN API
   ↓
5. If UAN found → Fetch employment history
   ↓
6. Determine candidate type (FRESHER/EXPERIENCED/EXPERIENCED_NO_UAN)
   ↓
7. AI analyzes CV with employment history context
   ↓
8. Results stored with PENDING status
   ↓
9. Staff reviews results via /secure/ai_cv_validation_results/{id}
   ↓
10. Staff submits final decision via /secure/submit_ai_cv_validation
    ↓
11. Check marked as COMPLETED or FAILED
```

## Red Flags Detected

### HIGH Severity
- Education-employment overlap (full-time study during full-time work)
- Major employment gaps (>6 months unexplained)
- UAN employment mismatch
- Fabricated companies or roles

### MEDIUM Severity
- Minor timeline inconsistencies
- Vague job descriptions
- Missing dates
- Unrealistic achievements

### LOW Severity
- Formatting issues
- Minor gaps (<3 months)
- Incomplete contact information

## Scoring System

**Authenticity Score (0-100)**:
- **90-100**: Highly authentic, verified
- **70-89**: Mostly authentic, minor concerns
- **50-69**: Moderate concerns, review required
- **0-49**: Significant red flags, likely issues

**Component Scores**:
- Education Score (0-100)
- Employment Score (0-100)
- Timeline Score (0-100)

## Files Modified

1. **utils/ai_utils.py**
   - Removed JD-related functions
   - Added `validate_cv_authenticity()` function
   - Focus on authenticity checks only

2. **main.py**
   - Updated `/secure/ai_cv_validation` endpoint
   - Removed CV/JD file upload requirement
   - Added PAN number parameter
   - Integrated UAN employment history fetch
   - Added candidate type detection

3. **apis.py**
   - No changes needed (already has UAN functions)

## Environment Requirements

```bash
# Required in .env
OPENAI_API_KEY=sk-...
SUREPASS_TOKEN=eyJhbGc...
```

## Notes

- Resume must be uploaded to candidate record before running validation
- PAN number is required to fetch UAN and employment history
- System automatically handles cases where UAN is not available
- All results require manual staff review before final submission
- Employment history is fetched asynchronously from Surepass API
