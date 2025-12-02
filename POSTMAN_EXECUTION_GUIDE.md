# Complete Postman Execution Guide for AI Endpoints

## 🚀 **Overview**
This guide provides step-by-step instructions for testing both AI systems:
1. **Resume Selection** - Basic resume processing (AI functionality removed)
2. **Internal Verification AI** - Document validation and manual verification workflow

---

# 📋 **System 1: AI Resume Selection**

## **How It Works**

### **🧠 AI Processing Flow**
```
JD File/Text → OpenAI GPT-4o mini → Structured Extraction
     ↓
Resume Files → OpenAI GPT-4o mini → Structured Extraction  
     ↓
Both Extracts → OpenAI Embeddings → Similarity Calculation
     ↓
Advanced Scoring → Filtering → Ranking → Top N Results
```

### **🔍 Detailed Process**
1. **Job Description Processing**:
   - Extract text from PDF/DOCX/TXT files
   - Use OpenAI GPT-4o mini to extract structured requirements
   - Generate embeddings using `text-embedding-3-large`

2. **Resume Processing** (for each resume):
   - Extract text from PDF/DOCX files
   - Use OpenAI GPT-4o mini to extract structured profile
   - Generate detailed analysis with strengths/weaknesses
   - Calculate multiple similarity scores

3. **Scoring System** (Triple-layer):
   - **Basic Similarity**: Cosine similarity between embeddings
   - **Enhanced Similarity**: Multi-factor weighted scoring
   - **Advanced Score**: OpenAI intelligent analysis (0-100)

4. **Filtering & Ranking**:
   - Apply minimum score thresholds
   - Filter by experience requirements
   - Check for required skills
   - Rank by advanced scores

## **🔧 Postman Setup for Resume Selection**

### **Step 1: Environment Setup**
Create a new Postman environment with these variables:
```json
{
  "base_url": "https://your-domain.com",
  "jwt_token": "your-actual-jwt-token-here"
}
```

### **Step 2: Request Configuration**
```
Method: POST
URL: {{base_url}}/secure/ai_resume_selection
Headers:
  Authorization: Bearer {{jwt_token}}
Body: form-data
```

### **Step 3: Form Data Setup**

#### **Option A: JD File Upload (Recommended)**
```
Key: jd_file
Type: File
Value: [Select your job_description.pdf/.docx/.txt file]

Key: resumes
Type: File  
Value: [Select resume1.pdf]

Key: resumes
Type: File
Value: [Select resume2.pdf]

Key: resumes
Type: File
Value: [Select resume3.pdf]

Key: top_count
Type: Text
Value: 5

Key: min_score
Type: Text
Value: 0.6

Key: min_experience
Type: Text
Value: 3

Key: required_skills
Type: Text
Value: Python,React,AWS,Docker

Key: include_detailed_analysis
Type: Text
Value: true
```

#### **Option B: JD Text (Fallback)**
```
Key: jd_text
Type: Text
Value: We are looking for a Senior Python Developer with 5+ years experience in Django, React, AWS, and Docker. Must have experience with microservices architecture and CI/CD pipelines.

Key: resumes
Type: File
Value: [Select resume files...]

[... other parameters same as above]
```

### **Step 4: Test Scripts**
Add this to the **Tests** tab in Postman:
```javascript
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

pm.test("Response has required fields", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData).to.have.property('topResumes');
    pm.expect(jsonData).to.have.property('batch_statistics');
    pm.expect(jsonData).to.have.property('pipelineRunId');
});

pm.test("Top resumes returned", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData.topResumes.length).to.be.greaterThan(0);
});

// Save pipeline ID for future use
const jsonData = pm.response.json();
pm.environment.set("pipeline_run_id", jsonData.pipelineRunId);

// Log results
console.log(`Processed ${jsonData.processing_summary.total_uploaded} resumes`);
console.log(`Top candidate score: ${jsonData.topResumes[0]?.enhanced_similarity}`);
```

### **Step 5: Expected Response**
```json
{
  "message": "Enhanced AI Resume Selection Completed",
  "pipelineRunId": "RUN_12345-uuid",
  "processing_summary": {
    "method": "Enhanced-OpenAI-Embeddings",
    "timestamp": "2024-01-15T10:30:00Z",
    "jd_source": "file",
    "jd_filename": "senior_python_developer.pdf",
    "total_uploaded": 10,
    "successfully_processed": 9,
    "processing_errors": 1,
    "passed_filters": 7,
    "filtered_out": 2
  },
  "filters_applied": {
    "top_count": 5,
    "min_score": 0.6,
    "min_experience": 3,
    "required_skills": ["Python", "React", "AWS", "Docker"]
  },
  "batch_statistics": {
    "score_statistics": {
      "enhanced_scores": {
        "average": 0.742,
        "highest": 0.923,
        "lowest": 0.234,
        "median": 0.756,
        "std_deviation": 0.156
      },
      "score_improvement": {
        "average_improvement": 0.087,
        "improvement_percentage": 77.8
      },
      "score_distribution": {
        "excellent": 2,
        "good": 4,
        "average": 2,
        "poor": 1
      }
    },
    "skills_analysis": {
      "total_unique_skills": 45,
      "top_skills": [
        {"skill": "python", "frequency": 8, "percentage": 88.9},
        {"skill": "javascript", "frequency": 6, "percentage": 66.7}
      ]
    },
    "recommendation_analysis": {
      "distribution": {"STRONG_HIRE": 2, "HIRE": 3, "MAYBE": 2},
      "hire_rate": 55.6,
      "strong_candidates": 2
    }
  },
  "topResumes": [
    {
      "fileName": "john_doe_senior_dev.pdf",
      "similarity": 0.78,
      "enhanced_similarity": 0.89,
      "advanced_score": 0.92,
      "recommendation": "STRONG_HIRE",
      "skills_matched": 12,
      "experience_match": 95,
      "overall_fit": 92,
      "resume_profile": {
        "technical_skills": {
          "programming_languages": ["Python", "JavaScript", "TypeScript"],
          "frameworks": ["Django", "React", "FastAPI"],
          "databases": ["PostgreSQL", "MongoDB"],
          "cloud_platforms": ["AWS", "Docker"]
        },
        "experience": {
          "total_years": 6,
          "positions": [...]
        }
      },
      "detailed_analysis": {
        "skills_analysis": {
          "matched_skills": [
            {"skill": "Python", "match_strength": "STRONG"},
            {"skill": "Django", "match_strength": "STRONG"}
          ],
          "missing_skills": [
            {"skill": "Kubernetes", "importance": "IMPORTANT"}
          ]
        },
        "strengths": [
          {"strength": "Strong Python expertise", "evidence": "6 years experience"}
        ],
        "overall_assessment": {
          "fit_percentage": 92,
          "recommendation": "STRONG_HIRE"
        }
      }
    }
  ]
}
```

---

# 🔍 **System 2: Internal Verification AI**

## **How It Works**

### **🧠 AI Processing Flow**
```
Verification Request → Manual Checks (PENDING)
     ↓
Staff Updates → OpenAI Validation (for AI checks)
     ↓
Education Certificate → OCR/PDF Extract → OpenAI Analysis
     ↓
Manual Verification → Status Update → Complete
```

### **🔍 Detailed Process**
1. **Internal Verification Types**:
   - **Address Verification**: Manual site visit/document check
   - **Resume Validation AI**: Automated resume authenticity analysis
   - **Education Manual**: Manual institution contact
   - **Education AI**: Automated certificate analysis
   - **Supervisory Check**: Manual phone verification
   - **Employment History**: Manual reference check

2. **AI Resume/CV Validation**:
   - Extract text from candidate's uploaded resume
   - Use OpenAI GPT-4o mini to analyze authenticity
   - Detect employment date overlaps and gaps
   - Identify inconsistent career progression
   - Check for AI-generated or template content
   - Validate technical skills claims

3. **AI Education Certificate Analysis**:
   - Extract text from uploaded certificate (PDF/DOCX)
   - Use OpenAI GPT-4o mini to validate authenticity
   - Check institution accreditation
   - Verify candidate name matching
   - Detect fraud patterns

4. **Manual Verification Workflow**:
   - Staff receives PENDING verification tasks
   - Performs manual checks (calls, visits, research)
   - Updates status through API with detailed remarks
   - System tracks all changes with timestamps

## **🔧 Postman Setup for Internal Verification**

### **Available Verification Check Types**
```
Manual Checks (require staff updates):
- address_verification
- education_check_manual  
- supervisory_check
- employment_history_manual

AI Checks (automatic processing):
- resume_validation (AI analysis of resume authenticity)
- education_check_ai (AI analysis of education certificates)
```

### **Endpoint 1: Get Verification Details**

#### **Request Setup**
```
Method: GET
URL: {{base_url}}/secure/getInternalVerificationDetails/{{verification_id}}
Headers:
  Authorization: Bearer {{jwt_token}}
```

#### **Path Variables**
```
verification_id: 507f1f77bcf86cd799439011
```

#### **Test Script**
```javascript
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

pm.test("Response has verification details", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData).to.have.property('verificationId');
    pm.expect(jsonData).to.have.property('candidateDetails');
    pm.expect(jsonData).to.have.property('internalVerifications');
});

// Log verification status
const jsonData = pm.response.json();
console.log(`Candidate: ${jsonData.candidateDetails.name}`);
console.log(`Overall Status: ${jsonData.overallStatus}`);
```

### **Endpoint 2: Upload Education Certificate**

#### **Request Setup**
```
Method: POST
URL: {{base_url}}/secure/uploadEducationCertificate
Headers:
  Authorization: Bearer {{jwt_token}}
Body: form-data
```

#### **Form Data**
```
Key: candidateId
Type: Text
Value: {{candidate_id}}

Key: file
Type: File
Value: [Select degree_certificate.pdf]
```

### **Endpoint 3: Test AI Resume Validation**

#### **How AI Resume Validation Works**
```
1. Candidate uploads resume during registration
2. Resume stored at candidate.resumePath
3. When verification stage includes "resume_validation":
   - System extracts text from resume (PDF/DOCX)
   - OpenAI GPT-4o mini analyzes for authenticity
   - Detects employment overlaps, gaps, inconsistencies
   - Identifies fake patterns, AI-generated content
   - Returns COMPLETED/FAILED with detailed analysis
```

#### **Testing AI Resume Validation**
```
Method: POST  
URL: {{base_url}}/secure/initiateStageVerification
Headers:
  Authorization: Bearer {{jwt_token}}
  Content-Type: application/json
Body: raw (JSON)
```

#### **Request Body for AI Resume Check**
```json
{
  "candidateId": "{{candidate_id}}",
  "organizationId": "{{organization_id}}",
  "stages": {
    "primary": [
      "resume_validation"
    ]
  }
}
```

#### **Expected AI Resume Validation Response**
```json
{
  "message": "Verification created with stage 'primary'",
  "verificationId": "verification_id_here",
  "stage": "primary"
}

// Then run the stage to get AI analysis:
POST /secure/runStage
{
  "verificationId": "verification_id_here", 
  "stage": "primary"
}

// AI Analysis Result:
{
  "status": "COMPLETED",
  "remarks": {
    "message": "Resume validation passed",
    "details": {
      "status": "VALID",
      "confidence_score": 87,
      "confidence_level": "HIGH",
      "issues": [],
      "positive_indicators": [
        "Consistent career progression",
        "Realistic skill development timeline"
      ],
      "red_flags": [],
      "career_analysis": {
        "progression_logical": true,
        "experience_years": 5,
        "skill_consistency": "Strong"
      },
      "explanation": "Resume shows authentic career progression with no suspicious patterns detected."
    }
  }
}
```

### **Endpoint 4: Update Manual Verification**

#### **Request Setup**
```
Method: POST
URL: {{base_url}}/secure/updateInternalVerification
Headers:
  Authorization: Bearer {{jwt_token}}
  Content-Type: application/json
Body: raw (JSON)
```

#### **Request Body Examples**

**Address Verification:**
```json
{
  "verificationId": "{{verification_id}}",
  "stage": "primary",
  "checkName": "address_verification",
  "status": "COMPLETED",
  "remarks": "Address verified through utility bill and site visit. Confirmed residential address matches records. Property ownership verified through municipal records. No discrepancies found.",
  "attachments": [
    "https://storage.com/utility_bill.pdf",
    "https://storage.com/property_tax_receipt.pdf"
  ]
}
```

**Education Manual Check:**
```json
{
  "verificationId": "{{verification_id}}",
  "stage": "primary", 
  "checkName": "education_check_manual",
  "status": "COMPLETED",
  "remarks": "Contacted university registrar office directly. Confirmed degree authenticity, graduation date (June 2018), and academic performance (First Class). All details match candidate claims. Registrar provided official verification letter.",
  "attachments": [
    "https://storage.com/university_verification_letter.pdf"
  ]
}
```

**Supervisory Check:**
```json
{
  "verificationId": "{{verification_id}}",
  "stage": "secondary",
  "checkName": "supervisory_check", 
  "status": "COMPLETED",
  "remarks": "Contacted previous employer HR department (TechCorp Ltd). Spoke with direct supervisor Mr. John Smith. Confirmed employment dates (Jan 2020 - Dec 2022), job role (Senior Developer), and responsibilities. Received positive feedback about candidate's technical skills, work ethic, and team collaboration. No disciplinary issues reported.",
  "attachments": []
}
```

**AI Resume Validation:**
```json
{
  "verificationId": "{{verification_id}}",
  "stage": "primary",
  "checkName": "resume_validation",
  "status": "COMPLETED",
  "remarks": "AI analysis completed. Resume shows authentic career progression with consistent employment timeline. No date overlaps or suspicious patterns detected. Technical skills align with experience level. Confidence score: 87%",
  "attachments": []
}
```

**Employment History Manual:**
```json
{
  "verificationId": "{{verification_id}}",
  "stage": "final",
  "checkName": "employment_history_manual",
  "status": "COMPLETED", 
  "remarks": "Verified complete employment history through multiple sources: HR records from 3 companies, LinkedIn profile cross-check, and reference calls. All employment dates and roles confirmed. No gaps or discrepancies found. Salary progression appears consistent with market standards.",
  "attachments": [
    "https://storage.com/employment_verification_report.pdf"
  ]
}
```

#### **Test Script**
```javascript
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

pm.test("Verification updated successfully", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData.message).to.include("updated successfully");
    pm.expect(jsonData).to.have.property('verificationId');
    pm.expect(jsonData).to.have.property('updatedBy');
});

// Log update details
const jsonData = pm.response.json();
console.log(`Updated: ${jsonData.checkName} to ${jsonData.status}`);
console.log(`Updated by: ${jsonData.updatedBy}`);
```

---

# 🎯 **Complete Testing Workflow**

## **Scenario 1: Resume Selection Workflow**

### **Step 1: Prepare Test Files**
- **JD File**: Create a job_description.pdf with detailed requirements
- **Resume Files**: Collect 5-10 sample resumes in PDF format
- **Expected**: Mix of good and poor matches for testing

### **Step 2: Basic Test**
```
1. Upload JD file + 3 resumes
2. Set top_count = 3
3. No filters (min_score = 0.0)
4. Check all resumes are processed
5. Verify ranking makes sense
```

### **Step 3: Advanced Test**
```
1. Upload JD file + 10 resumes  
2. Set filters: min_score = 0.7, min_experience = 5
3. Set required_skills = "Python,AWS"
4. Check filtering works correctly
5. Verify only qualified candidates returned
```

### **Step 4: Performance Test**
```
1. Upload JD + 50 resumes (max load test)
2. Measure response time
3. Check all resumes processed successfully
4. Verify statistics are accurate
```

## **Scenario 2: Internal Verification Workflow**

### **Step 1: Get Verification Details**
```
1. Call GET /getInternalVerificationDetails/{id}
2. Check candidate information
3. Identify PENDING verification checks
4. Note which checks need manual work
```

### **Step 2: Upload Education Certificate**
```
1. Upload candidate's degree certificate
2. Verify file upload successful
3. Check certificate path saved to candidate
4. Ready for AI analysis
```

### **Step 3: Run AI Verification Checks**
```
1. Resume Validation AI → Runs automatically (if resume uploaded)
2. Education Certificate AI → Runs automatically (if certificate uploaded)
3. Check AI analysis results and confidence scores
4. Verify AI checks completed successfully
```

### **Step 4: Complete Manual Verifications**
```
1. Address Verification → COMPLETED
2. Education Manual → COMPLETED  
3. Supervisory Check → COMPLETED
4. Employment History → COMPLETED
5. Verify all updates saved with timestamps
```

### **Step 4: Verify Final Status**
```
1. Call GET /getInternalVerificationDetails/{id} again
2. Check all verifications are COMPLETED
3. Verify overall verification status updated
4. Check audit trail is complete
```

---

# 🔧 **Troubleshooting Guide**

## **Common Issues**

### **Resume Selection Issues**
```
❌ "Could not extract text from JD file"
✅ Solution: Ensure JD file is valid PDF/DOCX/TXT with readable text

❌ "Resume file must be PDF or DOCX format"  
✅ Solution: Convert DOC files to DOCX, avoid image-only PDFs

❌ "OpenAI API error"
✅ Solution: Check OPENAI_API_KEY environment variable is set

❌ "No resumes passed filters"
✅ Solution: Lower min_score or reduce required_skills
```

### **Internal Verification Issues**
```
❌ "Verification not found"
✅ Solution: Check verification ID is valid ObjectId format

❌ "You are not authorized to update this verification"
✅ Solution: Ensure user has correct role and organization access

❌ "Check not found in stage"
✅ Solution: Verify checkName and stage combination exists
```

## **Performance Optimization**

### **Resume Selection**
- **File Size**: Keep resume files under 5MB each
- **Batch Size**: Process max 20 resumes at once for best performance
- **Detailed Analysis**: Set to false for faster processing when not needed

### **Internal Verification**
- **Concurrent Updates**: Avoid updating same verification simultaneously
- **File Uploads**: Compress certificate files before upload
- **Remarks Length**: Keep remarks under 1000 characters for better performance

---

# 📊 **Success Metrics**

## **Resume Selection**
- ✅ **Processing Success Rate**: >95% of resumes processed without errors
- ✅ **Response Time**: <30 seconds for 10 resumes
- ✅ **Ranking Accuracy**: Top candidates should match manual assessment
- ✅ **Filter Effectiveness**: Filters should reduce candidate pool appropriately

## **Internal Verification**  
- ✅ **Update Success Rate**: 100% of manual updates should save correctly
- ✅ **Audit Trail**: All changes tracked with user and timestamp
- ✅ **Status Consistency**: Overall status should reflect individual check statuses
- ✅ **File Upload**: Education certificates should upload and process successfully

This guide provides everything needed to successfully test both AI systems using Postman!