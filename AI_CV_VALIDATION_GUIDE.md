# AI CV Validation Check - Complete Guide

## 📋 **Overview**

The AI CV Validation check is a new verification type that uses OpenAI GPT-4o mini to analyze candidate CVs against job descriptions. It works exactly like other verification checks (education_check_manual, supervisory_check, etc.) and integrates seamlessly into the existing verification workflow.

## 🔧 **How It Works**

### **1. Verification Flow Integration**
- ✅ Works like all other verification checks
- ✅ Updates verification status and progress automatically
- ✅ Contributes to overall completion percentage
- ✅ Can be added to any stage (primary, secondary, final)
- ✅ Supports role-based access control

### **2. Status Progression**
```
NOT_STARTED → PENDING (Upload) → PENDING (Review) → COMPLETED/FAILED
```

- **NOT_STARTED**: Check not yet initiated
- **PENDING (Upload)**: Waiting for staff to upload CV and JD for AI analysis
- **PENDING (Review)**: AI analysis completed, waiting for staff review and submission
- **COMPLETED**: Staff reviewed AI analysis and approved the candidate
- **FAILED**: Staff reviewed AI analysis and rejected the candidate

### **3. Progress Calculation**
The AI CV validation check contributes to the overall verification progress just like other checks:
- Each check has equal weight in progress calculation
- Completion percentage updates automatically when check status changes
- Progress is calculated as: `(completed_checks / total_checks) * 100`

---

## 🚀 **Setup Guide**

### **Step 1: Configure OpenAI API Key**

1. **Get OpenAI API Key**:
   - Go to https://platform.openai.com/api-keys
   - Create a new API key
   - Copy the key (starts with `sk-proj-...`)

2. **Add to AWS Secrets Manager**:
   ```json
   {
     "SUREPASS_TOKEN": "your-surepass-token",
     "MONGO_URI": "your-mongo-uri",
     "OPENAI_API_KEY": "sk-proj-your-openai-key-here",
     "SESSION_SECRET": "your-session-secret"
   }
   ```

3. **Or Add to .env file** (for local development):
   ```env
   OPENAI_API_KEY=sk-proj-your-openai-key-here
   ```

### **Step 2: Add AI CV Validation to Verification Stages**

When creating a verification request, include `ai_cv_validation` in any stage:

```json
{
  "candidateId": "candidate_object_id",
  "organizationId": "org_object_id", 
  "stages": {
    "primary": [
      "pan_verification",
      "aadhaar_verification",
      "ai_cv_validation"
    ],
    "secondary": [
      "education_check_manual",
      "employment_history"
    ],
    "final": [
      "supervisory_check",
      "court_record"
    ]
  }
}
```

---

## 📝 **How to Perform AI CV Validation**

### **Step 1: Check Verification Status**

First, get the verification details to see pending checks:

```bash
GET /secure/getVerificationDetails/{verificationId}
```

Look for `ai_cv_validation` check with status `PENDING`:
```json
{
  "checkName": "ai_cv_validation",
  "status": "PENDING",
  "requiresManualVerification": true,
  "requiresAIAnalysis": true,
  "instructions": "Upload candidate's CV/Resume and Job Description for AI-powered analysis and scoring"
}
```

### **Step 2: Upload CV and JD for AI Analysis**

Use the AI CV validation endpoint to get AI analysis:

```bash
POST /secure/ai_cv_validation
Content-Type: multipart/form-data

Parameters:
- verificationId: "verification_object_id"
- cv_file: candidate_resume.pdf (or .docx)
- jd_file: job_description.pdf (optional)
- jd_text: "Job description text..." (optional, used if no file)
```

**Example using curl:**
```bash
curl -X POST "http://localhost:8000/secure/ai_cv_validation" \
  -H "Authorization: Bearer your-jwt-token" \
  -F "verificationId=674a1234567890abcdef1234" \
  -F "cv_file=@candidate_resume.pdf" \
  -F "jd_file=@job_description.pdf"
```

**Example using Postman:**
1. Method: POST
2. URL: `{{base_url}}/secure/ai_cv_validation`
3. Headers: `Authorization: Bearer {{jwt_token}}`
4. Body: form-data
   - `verificationId`: verification ID
   - `cv_file`: Upload CV file
   - `jd_file`: Upload JD file (or use `jd_text`)

### **Step 3: Review AI Analysis Results**

The response includes comprehensive AI analysis (status remains PENDING for manual review):

```json
{
  "message": "AI CV analysis completed successfully. Please review and submit the check.",
  "verificationId": "674a1234567890abcdef1234",
  "candidateName": "John Doe",
  "analysis": {
    "overall_score": 85,
    "hiring_recommendation": "HIRE",
    "skills_analysis": {
      "matching_skills": ["Python", "React", "MongoDB", "REST APIs"],
      "missing_critical_skills": ["AWS", "Docker"],
      "skills_score": 78
    },
    "experience_analysis": {
      "meets_minimum_experience": true,
      "total_experience_years": 5.5,
      "experience_score": 90
    },
    "strengths": [
      "Strong technical background in required technologies",
      "Relevant project experience",
      "Good career progression"
    ],
    "weaknesses": [
      "Missing cloud platform experience",
      "No containerization experience"
    ],
    "recommendations": [
      "Consider for role with AWS training",
      "Strong candidate overall despite missing cloud skills"
    ]
  }
}
```

### **Step 4: Submit Final Decision**

After reviewing AI analysis, submit your final decision:

```bash
POST /secure/submit_ai_cv_validation
Content-Type: multipart/form-data

Parameters:
- verificationId: "verification_object_id"
- final_status: "COMPLETED" or "FAILED"
- staff_remarks: "Additional comments from staff review"
```

**Example:**
```bash
curl -X POST "http://localhost:8000/secure/submit_ai_cv_validation" \
  -H "Authorization: Bearer your-jwt-token" \
  -F "verificationId=674a1234567890abcdef1234" \
  -F "final_status=COMPLETED" \
  -F "staff_remarks=Good candidate despite missing cloud skills. Recommend for hire with training."
```

### **Step 5: Verify Final Status Update**

Check that the verification status updated:

```bash
GET /secure/getVerificationDetails/{verificationId}
```

The `ai_cv_validation` check should now show:
```json
{
  "checkName": "ai_cv_validation",
  "status": "COMPLETED",
  "submittedAt": "2024-01-15T10:30:00Z",
  "updatedBy": "staff@company.com",
  "staffRemarks": "Good candidate despite missing cloud skills. Recommend for hire with training.",
  "finalDecision": "COMPLETED",
  "remarks": "AI Score: 85/100, AI Recommendation: HIRE. Staff Review: Good candidate despite missing cloud skills. Recommend for hire with training.",
  "aiAnalysis": {
    "overall_score": 85,
    "hiring_recommendation": "HIRE",
    // ... full analysis results
  }
}
```

---

## 📊 **Understanding AI Analysis Results**

### **Overall Score (0-100)**
- **90-100**: Excellent match
- **80-89**: Very good match  
- **70-79**: Good match
- **60-69**: Fair match
- **Below 60**: Poor match

### **Hiring Recommendations**
- **STRONG_HIRE**: Exceptional candidate, highly recommended
- **HIRE**: Good candidate, recommended for hiring
- **MAYBE**: Borderline candidate, requires discussion
- **NO_HIRE**: Not recommended for the role

### **Skills Analysis**
- **Matching Skills**: Skills candidate has that match job requirements
- **Missing Critical Skills**: Required skills candidate lacks
- **Missing Nice-to-Have**: Preferred skills candidate lacks
- **Additional Skills**: Extra skills candidate brings

### **Experience Analysis**
- **Meets Minimum Experience**: Boolean check for years requirement
- **Total Experience Years**: Candidate's total work experience
- **Experience Score**: Quality and relevance of experience (0-100)

---

## 🔄 **Complete Verification Workflow**

### **Example: Full Verification Process**

1. **Create Verification Request**:
   ```json
   {
     "stages": {
       "primary": ["pan_verification", "ai_cv_validation"],
       "secondary": ["education_check_manual"],
       "final": ["supervisory_check"]
     }
   }
   ```

2. **Initial Status** (0% complete):
   ```json
   {
     "overallStatus": "IN_PROGRESS",
     "currentStage": "primary",
     "progress": {
       "completed": 0,
       "total": 4,
       "percentage": 0
     }
   }
   ```

3. **After PAN Verification** (25% complete):
   ```json
   {
     "progress": {
       "completed": 1,
       "total": 4, 
       "percentage": 25
     }
   }
   ```

4. **After AI CV Validation** (50% complete):
   ```json
   {
     "progress": {
       "completed": 2,
       "total": 4,
       "percentage": 50
     }
   }
   ```

5. **Continue until all checks complete** (100%):
   ```json
   {
     "overallStatus": "COMPLETED",
     "progress": {
       "completed": 4,
       "total": 4,
       "percentage": 100
     }
   }
   ```

---

## 🛠 **API Reference**

### **1. Upload CV and JD for AI Analysis**
```
POST /secure/ai_cv_validation
```

**Parameters:**
- `verificationId` (required): Verification record ID
- `cv_file` (required): CV/Resume file (PDF/DOCX)
- `jd_file` (optional): Job description file (PDF/DOCX/TXT)
- `jd_text` (optional): Job description as text

**Response:** AI analysis results with scoring and recommendations (status remains PENDING)

### **2. Submit Final Decision**
```
POST /secure/submit_ai_cv_validation
```

**Parameters:**
- `verificationId` (required): Verification record ID
- `final_status` (required): "COMPLETED" or "FAILED"
- `staff_remarks` (optional): Additional staff comments

**Response:** Confirmation of submission

### **3. Get AI CV Validation Results**
```
GET /secure/ai_cv_validation_results/{verificationId}
```

**Response:** Detailed AI analysis results for the verification

### **4. Get Verification Details**
```
GET /secure/getVerificationDetails/{verificationId}
```

**Response:** Complete verification status including AI CV validation results

---

## 🔐 **Access Control**

The AI CV validation check follows the same role-based access control as other verification checks:

- **SUPER_ADMIN/SUPER_SPOC**: Can perform for any candidate
- **SPOC** (BGV staff): Can perform for any candidate
- **SUPER_ADMIN_HELPER**: Can perform for accessible organizations
- **ORG_HR/SPOC**: Can perform for their organization's candidates
- **HELPER**: Can perform for candidates they created

---

## ⚠️ **Important Notes**

1. **OpenAI API Key Required**: The system requires a valid OpenAI API key to function
2. **File Formats**: Supports PDF and DOCX for CVs, PDF/DOCX/TXT for JDs
3. **Manual Process**: Like other manual checks, requires staff intervention
4. **Status Updates**: Automatically updates verification progress and status
5. **Cost**: Uses OpenAI API (small cost per analysis, typically $0.01-0.05)

---

## 🐛 **Troubleshooting**

### **Common Issues:**

1. **"OpenAI client not configured"**
   - Solution: Add OPENAI_API_KEY to environment variables or AWS Secrets Manager

2. **"Could not extract meaningful text from CV"**
   - Solution: Ensure CV is not image-only PDF, use text-based documents

3. **"AI validation failed"**
   - Solution: Check OpenAI API key validity and account credits

4. **"AI CV validation check not found in verification stages"**
   - Solution: Ensure `ai_cv_validation` is included in the verification stages

### **Testing:**

Use the test endpoint to verify OpenAI integration:
```bash
POST /secure/ai_cv_validation
# Upload sample CV and JD to test the system
```

---

## 📈 **Best Practices**

1. **Stage Placement**: Add AI CV validation to primary or secondary stage for early screening
2. **File Quality**: Use text-based PDFs for better extraction results  
3. **JD Quality**: Provide detailed job descriptions for better analysis
4. **Review Results**: Always review AI recommendations alongside human judgment
5. **Training**: Train staff on interpreting AI analysis results

---

This AI CV validation check seamlessly integrates with your existing verification system while providing powerful AI-driven insights for hiring decisions!