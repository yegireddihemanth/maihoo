# UI Developer Guide - AI CV Validation Feature

## 📋 Overview

This document provides complete specifications for building the UI for the **AI CV Authenticity Validation** feature. This feature allows staff to upload a candidate's resume and get an AI-powered authenticity analysis with UAN verification.

---

## 🎯 Feature Purpose

**What it does:**
- Validates CV/Resume authenticity (NOT job matching)
- Checks for education-employment overlaps, timeline gaps, red flags
- Verifies if candidate has UAN (formal employment record)
- Provides authenticity score (0-100) with positive and negative findings
- Requires manual staff review before final submission

**What it does NOT do:**
- Compare CV with Job Description
- Provide hiring recommendations
- Auto-approve/reject candidates

---

## 🔗 API Endpoints

### 1. Run AI CV Validation

**Endpoint:** `POST /secure/ai_cv_validation`

**Purpose:** Upload resume and run AI authenticity check

**Request:**
```
POST /secure/ai_cv_validation
Authorization: Bearer {token}
Content-Type: multipart/form-data

Fields:
- verificationId: string (required)
- resume: file (optional - PDF/DOCX file upload)
- panNumber: string (optional - PAN like "BGTPH3610P")
- hasUan: string (optional - "yes" or "no")
```

**Resume Handling (Automatic):**

The endpoint has **2 modes** - UI only sends these 4 fields above:

1. **Mode 1: With File Upload**
   - UI includes `resume` file in request
   - Backend uses uploaded file
   
2. **Mode 2: Without File Upload**
   - UI does NOT include `resume` file
   - Backend automatically fetches from `candidate.resumePath` in database
   - Backend detects if it's S3 URL or local path
   - If S3 URL → Backend downloads automatically
   - If local path → Backend uses directly

**Important:** 
- UI **never sends** the resume path
- Backend **automatically** gets it from database
- Backend **automatically** handles S3 downloads

**Response:**
```json
{
  "message": "AI CV authenticity check completed successfully. Please review and submit.",
  "verificationId": "692eac5ff0a401b70b9d0dc9",
  "candidateName": "John Doe",
  "candidateType": "EXPERIENCED_WITH_UAN",
  "uanNumber": "101848108802",
  "hasUan": true,
  "uanVerificationNote": "✅ UAN verified: 101848108802. Candidate has formal employment history registered with EPFO.",
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
      "UAN verified - formal employment confirmed",
      "Clear timeline with no gaps",
      "Consistent career progression",
      "Professional presentation"
    ],
    "negative_findings": [
      "Minor gap of 2 months between jobs"
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
        "ABC Tech, Senior Engineer, 2020-Present",
        "XYZ Corp, Engineer, 2018-2020"
      ],
      "gaps_detected": true,
      "gap_details": ["2-month gap between jobs"],
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
        "description": "2-month gap between jobs - likely normal transition"
      }
    ],
    "summary": "CV appears authentic with verified UAN. Minor gap detected but within acceptable range."
  }
}
```

---

### 2. Get AI Validation Results

**Endpoint:** `GET /secure/ai_cv_validation_results/{verificationId}`

**Purpose:** Retrieve previously run AI analysis results

**Request:**
```
GET /secure/ai_cv_validation_results/692eac5ff0a401b70b9d0dc9
Authorization: Bearer {token}
```

**Response:**
```json
{
  "verificationId": "692eac5ff0a401b70b9d0dc9",
  "candidateName": "John Doe",
  "candidateEmail": "john@example.com",
  "candidateType": "EXPERIENCED_WITH_UAN",
  "uanNumber": "101848108802",
  "hasUan": true,
  "aiAnalysis": {
    "authenticity_score": 85,
    "recommendation": "APPROVE",
    "positive_findings": [...],
    "negative_findings": [...],
    "red_flags": [...]
  },
  "status": "PENDING",
  "remarks": "AI authenticity check completed. Score: 85/100. Awaiting manual review."
}
```

---

### 3. Submit Final Decision

**Endpoint:** `POST /secure/submit_ai_cv_validation`

**Purpose:** Submit staff's final decision after reviewing AI results

**Request:**
```
POST /secure/submit_ai_cv_validation
Authorization: Bearer {token}
Content-Type: application/x-www-form-urlencoded

Fields:
- verificationId: string (required)
- final_status: string (required - "COMPLETED" or "FAILED")
- staff_remarks: string (optional)
```

**Response:**
```json
{
  "message": "AI CV authenticity validation submitted as COMPLETED successfully",
  "verificationId": "692eac5ff0a401b70b9d0dc9",
  "candidateName": "John Doe",
  "finalStatus": "COMPLETED",
  "staffRemarks": "Reviewed AI analysis. UAN verified. Approved."
}
```

---

## 🎨 UI Design Specifications

### Page 1: AI CV Validation Form

**Location:** Verification Details Page → AI CV Validation Check

**Components:**

#### 1. Header Section
```
┌─────────────────────────────────────────────┐
│ 🤖 AI CV Authenticity Validation           │
│                                             │
│ Candidate: John Doe                         │
│ Verification ID: 692eac5ff0a401b70b9d0dc9  │
└─────────────────────────────────────────────┘
```

#### 2. Upload Section
```
┌─────────────────────────────────────────────┐
│ 📄 Resume Upload (Optional)                 │
│                                             │
│ ┌─────────────────────────────────────┐   │
│ │  Drag & Drop Resume Here            │   │
│ │  or Click to Browse                 │   │
│ │  (PDF/DOCX only)                    │   │
│ └─────────────────────────────────────┘   │
│                                             │
│ ℹ️ Resume Handling:                        │
│ • Upload new file here, OR                  │
│ • Skip if resume already in database        │
│ • System auto-fetches from S3/local path    │
│                                             │
│ Current Resume: ✅ Available in database    │
│ (or ❌ No resume found - upload required)   │
└─────────────────────────────────────────────┘
```

#### 3. UAN Verification Section
```
┌─────────────────────────────────────────────┐
│ 🔍 UAN Verification (Optional)              │
│                                             │
│ Choose one option:                          │
│                                             │
│ ○ Auto-check via PAN                        │
│   PAN Number: [BGTPH3610P]                 │
│   (System will check if UAN exists)         │
│                                             │
│ ○ Manual Override                           │
│   Does candidate have UAN?                  │
│   ◉ Yes  ○ No  ○ Unknown                   │
│                                             │
│ ○ Skip UAN Check                            │
│   (Proceed without UAN verification)        │
│                                             │
│ ℹ️ UAN = Universal Account Number (EPFO)   │
│    Indicates formal employment history      │
└─────────────────────────────────────────────┘
```

#### 4. Action Buttons
```
┌─────────────────────────────────────────────┐
│                                             │
│  [Cancel]  [Run AI Analysis] ← Primary     │
│                                             │
└─────────────────────────────────────────────┘
```

---

### Page 2: AI Analysis Results

**Shown after clicking "Run AI Analysis"**

#### 1. Score Card (Top)
```
┌─────────────────────────────────────────────┐
│ 🎯 Authenticity Score: 85/100               │
│                                             │
│ ████████████████████░░░░  85%              │
│                                             │
│ Recommendation: ✅ APPROVE                  │
│ Candidate Type: EXPERIENCED_WITH_UAN        │
│ UAN Status: ✅ Verified (101848108802)     │
└─────────────────────────────────────────────┘
```

**Score Color Coding:**
- 90-100: Green (Highly Authentic)
- 70-89: Blue (Authentic)
- 50-69: Yellow (Review Required)
- 0-49: Red (High Risk)

#### 2. Candidate Profile
```
┌─────────────────────────────────────────────┐
│ 👤 Candidate Profile                        │
│                                             │
│ Total Experience: 5 years                   │
│ Education Level: Bachelor's                 │
│ Career Progression: CONSISTENT              │
│ Timeline Clarity: CLEAR                     │
└─────────────────────────────────────────────┘
```

#### 3. Positive Findings (Green Section)
```
┌─────────────────────────────────────────────┐
│ ✅ Positive Findings (4)                    │
│                                             │
│ • UAN verified - formal employment confirmed│
│ • Clear timeline with no gaps               │
│ • Consistent career progression             │
│ • Professional presentation                 │
└─────────────────────────────────────────────┘
```

#### 4. Negative Findings (Yellow/Red Section)
```
┌─────────────────────────────────────────────┐
│ ⚠️ Negative Findings (1)                    │
│                                             │
│ • Minor gap of 2 months between jobs        │
└─────────────────────────────────────────────┘
```

#### 5. Red Flags (If any)
```
┌─────────────────────────────────────────────┐
│ 🚩 Red Flags (1)                            │
│                                             │
│ [LOW] Employment Gap                        │
│ 2-month gap between jobs - likely normal    │
│ transition period                           │
└─────────────────────────────────────────────┘
```

**Red Flag Severity Colors:**
- HIGH: Red background
- MEDIUM: Orange background
- LOW: Yellow background

#### 6. Detailed Analysis (Expandable Sections)

**Education Analysis:**
```
┌─────────────────────────────────────────────┐
│ 🎓 Education Analysis [Expand ▼]           │
│                                             │
│ Score: 95/100                               │
│ Overlaps Detected: No                       │
│                                             │
│ Education Entries:                          │
│ • Bachelor of Technology, XYZ University,   │
│   2014-2018                                 │
└─────────────────────────────────────────────┘
```

**Employment Analysis:**
```
┌─────────────────────────────────────────────┐
│ 💼 Employment Analysis [Expand ▼]          │
│                                             │
│ Score: 85/100                               │
│ UAN Verification: MATCHED                   │
│ Gaps Detected: Yes (1)                      │
│                                             │
│ Employment Entries:                         │
│ • ABC Tech, Senior Engineer, 2020-Present   │
│ • XYZ Corp, Engineer, 2018-2020             │
│                                             │
│ Gap Details:                                │
│ • 2-month gap between jobs                  │
└─────────────────────────────────────────────┘
```

**Timeline Analysis:**
```
┌─────────────────────────────────────────────┐
│ 📅 Timeline Analysis [Expand ▼]            │
│                                             │
│ Score: 90/100                               │
│ Timeline Consistent: Yes                    │
│ Issues: None                                │
└─────────────────────────────────────────────┘
```

#### 7. AI Summary
```
┌─────────────────────────────────────────────┐
│ 📝 AI Summary                               │
│                                             │
│ CV appears authentic with verified UAN.     │
│ Minor gap detected but within acceptable    │
│ range. Candidate has formal employment      │
│ history registered with EPFO.               │
└─────────────────────────────────────────────┘
```

#### 8. Staff Decision Section
```
┌─────────────────────────────────────────────┐
│ 👨‍💼 Staff Review & Decision                 │
│                                             │
│ Final Decision:                             │
│ ◉ Approve (COMPLETED)                       │
│ ○ Reject (FAILED)                           │
│                                             │
│ Staff Remarks:                              │
│ ┌─────────────────────────────────────┐   │
│ │ Reviewed AI analysis. UAN verified. │   │
│ │ Employment gap explained. Approved. │   │
│ └─────────────────────────────────────┘   │
│                                             │
│ [Cancel]  [Submit Decision] ← Primary      │
└─────────────────────────────────────────────┘
```

---

## 🔄 User Flow

### Flow 1: New AI Validation (With File Upload)

```
1. Staff opens verification record
   ↓
2. Clicks "AI CV Validation" check
   ↓
3. Sees upload form
   ↓
4. Uploads NEW resume file
   ↓
5. Optionally provides PAN or manual UAN status
   ↓
6. Clicks "Run AI Analysis"
   ↓
7. Loading spinner (5-15 seconds)
   ↓
8. Results page appears
   ↓
9. Staff reviews all sections
   ↓
10. Staff makes decision (Approve/Reject)
    ↓
11. Adds remarks
    ↓
12. Clicks "Submit Decision"
    ↓
13. Check marked as COMPLETED/FAILED
```

### Flow 1b: New AI Validation (Using Database Resume)

```
1. Staff opens verification record
   ↓
2. Clicks "AI CV Validation" check
   ↓
3. Sees upload form
   ↓
4. Sees "✅ Resume available in database"
   ↓
5. Skips file upload (uses existing resume)
   ↓
6. Optionally provides PAN or manual UAN status
   ↓
7. Clicks "Run AI Analysis"
   ↓
8. System fetches resume from S3/local path
   ↓
9. Loading spinner (5-15 seconds)
   ↓
10. Results page appears
    ↓
11. Staff reviews and submits decision
```

### Flow 2: Review Existing Results

```
1. Staff opens verification record
   ↓
2. Clicks "AI CV Validation" check
   ↓
3. System detects AI analysis already done
   ↓
4. Shows results page directly
   ↓
5. Staff reviews
   ↓
6. Staff submits decision
```

---

## 🎨 UI States

### State 1: Initial (No Analysis)
- Show upload form
- Show UAN verification options
- "Run AI Analysis" button enabled

### State 2: Loading
- Show spinner/progress bar
- Message: "Analyzing resume... This may take 10-15 seconds"
- Disable all inputs

### State 3: Results Ready
- Show all analysis sections
- Show staff decision form
- "Submit Decision" button enabled

### State 4: Submitted
- Show success message
- Disable all inputs
- Show final status badge (COMPLETED/FAILED)

### State 5: Error
- Show error message
- Allow retry
- Show "Run AI Analysis" button again

---

## 📊 Data Display Guidelines

### Authenticity Score
```javascript
function getScoreColor(score) {
  if (score >= 90) return 'green';
  if (score >= 70) return 'blue';
  if (score >= 50) return 'yellow';
  return 'red';
}

function getScoreLabel(score) {
  if (score >= 90) return 'Highly Authentic';
  if (score >= 70) return 'Authentic';
  if (score >= 50) return 'Review Required';
  return 'High Risk';
}
```

### Recommendation Badge
```javascript
function getRecommendationBadge(recommendation) {
  switch(recommendation) {
    case 'APPROVE':
      return <Badge color="green">✅ Approve</Badge>;
    case 'REVIEW_REQUIRED':
      return <Badge color="yellow">⚠️ Review Required</Badge>;
    case 'REJECT':
      return <Badge color="red">❌ Reject</Badge>;
  }
}
```

### Candidate Type Badge
```javascript
function getCandidateTypeBadge(type) {
  switch(type) {
    case 'EXPERIENCED_WITH_UAN':
      return <Badge color="green">✅ Experienced (UAN Verified)</Badge>;
    case 'EXPERIENCED_NO_UAN':
      return <Badge color="yellow">⚠️ Experienced (No UAN)</Badge>;
    case 'FRESHER':
      return <Badge color="blue">🎓 Fresher</Badge>;
    case 'UNKNOWN':
      return <Badge color="gray">❓ Unknown</Badge>;
  }
}
```

### Red Flag Severity
```javascript
function getRedFlagColor(severity) {
  switch(severity) {
    case 'HIGH': return 'red';
    case 'MEDIUM': return 'orange';
    case 'LOW': return 'yellow';
  }
}
```

---

## � Resumie Source Detection

The UI should detect and display the resume source to the user:

### Check Resume Availability
```javascript
async function checkResumeAvailability(candidateId) {
  const response = await fetch(`/secure/candidates/${candidateId}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  
  const candidate = await response.json();
  const resumePath = candidate.resumePath;
  
  if (!resumePath) {
    return {
      available: false,
      message: "❌ No resume found. Upload required.",
      source: null
    };
  }
  
  // Detect source
  if (resumePath.startsWith('http://') || 
      resumePath.startsWith('https://') || 
      resumePath.startsWith('s3://')) {
    return {
      available: true,
      message: "✅ Resume available in S3",
      source: "S3",
      path: resumePath
    };
  } else {
    return {
      available: true,
      message: "✅ Resume available (local storage)",
      source: "LOCAL",
      path: resumePath
    };
  }
}
```

### Display in UI
```
┌─────────────────────────────────────────────┐
│ 📄 Resume Status                            │
│                                             │
│ ✅ Resume Available                         │
│ Source: S3 Bucket                           │
│ Path: https://bucket.s3.../resume.pdf      │
│                                             │
│ [Upload New Resume] (optional)              │
└─────────────────────────────────────────────┘
```

---

## 🔔 Notifications & Messages

### Success Messages
- "AI analysis completed successfully!"
- "Decision submitted successfully!"
- "Resume fetched from S3 successfully!"

### Error Messages
- "Failed to upload resume. Please try again."
- "AI analysis failed. Please check resume format."
- "Network error. Please try again."
- "Resume not found in database. Please upload resume first."
- "Failed to download resume from S3. Please check URL."

### Warning Messages
- "UAN verification failed. Continuing with CV analysis only."
- "No PAN provided. UAN verification skipped."
- "Resume download from S3 taking longer than expected..."

### Info Messages
- "AI analysis takes 10-15 seconds. Please wait..."
- "Resume already uploaded to candidate record."
- "UAN verified - candidate has formal employment history."
- "Using resume from S3 bucket..."
- "Using resume from local storage..."

---

## 📱 Responsive Design

### Desktop (>1024px)
- Two-column layout for results
- Left: Score card + findings
- Right: Detailed analysis sections

### Tablet (768px - 1024px)
- Single column layout
- Collapsible sections

### Mobile (<768px)
- Single column
- All sections collapsed by default
- Sticky header with score

---

## 🎯 Key UI/UX Considerations

### 1. Loading State
- Show clear progress indicator
- Estimated time: "Analyzing... ~10-15 seconds"
- Don't allow navigation away during analysis

### 2. Error Handling
- Clear error messages
- Retry button
- Contact support link if repeated failures

### 3. Data Validation
- Resume file: PDF/DOCX only, max 10MB
- PAN format: 10 characters (e.g., BGTPH3610P)
- Staff remarks: Optional but recommended

### 4. Accessibility
- Color-blind friendly (use icons + colors)
- Keyboard navigation
- Screen reader support
- ARIA labels

### 5. Performance
- Lazy load detailed sections
- Cache results
- Optimistic UI updates

---

## 🧪 Test Scenarios

### Test Case 1: High Score with UAN
```
Input:
- Resume: Clean CV with 5 years experience
- PAN: Valid PAN with UAN

Expected Output:
- Score: 85-95
- Candidate Type: EXPERIENCED_WITH_UAN
- Recommendation: APPROVE
- Few/no red flags
```

### Test Case 2: Low Score with Red Flags
```
Input:
- Resume: CV with education-employment overlap
- No UAN

Expected Output:
- Score: 30-50
- Candidate Type: EXPERIENCED_NO_UAN
- Recommendation: REJECT
- Multiple HIGH severity red flags
```

### Test Case 3: Fresher
```
Input:
- Resume: Fresh graduate, no experience
- No UAN

Expected Output:
- Score: 75-90
- Candidate Type: FRESHER
- Recommendation: APPROVE
- Focus on education analysis
```

---

## 📦 API Integration Code Examples

### Example 1: Run AI Validation (With File Upload)
```javascript
async function runAIValidation(verificationId, resumeFile, panNumber, hasUan) {
  const formData = new FormData();
  formData.append('verificationId', verificationId);
  
  // Option 1: Upload new resume file
  if (resumeFile) {
    formData.append('resume', resumeFile);
  }
  // Option 2: If no file, system fetches from candidate.resumePath (S3/local)
  
  if (panNumber) {
    formData.append('panNumber', panNumber);
  }
  
  if (hasUan) {
    formData.append('hasUan', hasUan); // "yes" or "no"
  }
  
  const response = await fetch('/secure/ai_cv_validation', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
    },
    body: formData
  });
  
  return await response.json();
}
```

### Example 1b: Run AI Validation (Without File - Use Database Resume)
```javascript
async function runAIValidationFromDatabase(verificationId, panNumber, hasUan) {
  const formData = new FormData();
  formData.append('verificationId', verificationId);
  
  // No resume file - system will fetch from candidate.resumePath
  // Supports S3 URLs and local paths automatically
  
  if (panNumber) {
    formData.append('panNumber', panNumber);
  }
  
  if (hasUan) {
    formData.append('hasUan', hasUan);
  }
  
  const response = await fetch('/secure/ai_cv_validation', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
    },
    body: formData
  });
  
  return await response.json();
}
```

### Example 2: Get Results
```javascript
async function getAIResults(verificationId) {
  const response = await fetch(
    `/secure/ai_cv_validation_results/${verificationId}`,
    {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    }
  );
  
  return await response.json();
}
```

### Example 3: Submit Decision
```javascript
async function submitDecision(verificationId, finalStatus, staffRemarks) {
  const formData = new URLSearchParams();
  formData.append('verificationId', verificationId);
  formData.append('final_status', finalStatus); // "COMPLETED" or "FAILED"
  formData.append('staff_remarks', staffRemarks);
  
  const response = await fetch('/secure/submit_ai_cv_validation', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: formData
  });
  
  return await response.json();
}
```

---

## 🎨 Design Assets Needed

### Icons
- 🤖 AI/Robot icon
- 📄 Document/Resume icon
- 🔍 Search/Verification icon
- ✅ Checkmark (success)
- ⚠️ Warning triangle
- 🚩 Red flag
- 🎓 Education cap
- 💼 Briefcase (employment)
- 📅 Calendar (timeline)
- 👤 User profile

### Colors
- Success Green: #10B981
- Warning Yellow: #F59E0B
- Error Red: #EF4444
- Info Blue: #3B82F6
- Neutral Gray: #6B7280

---

## ✅ Checklist for UI Developer

### Resume Handling
- [ ] Check if candidate has resume in database
- [ ] Display resume source (S3/Local/None)
- [ ] Create upload form with drag-drop
- [ ] Allow skipping upload if resume exists
- [ ] Show resume path/URL to user
- [ ] Handle both upload and database resume flows

### UAN Verification
- [ ] Add PAN input with validation (10 chars)
- [ ] Add manual UAN override (yes/no radio)
- [ ] Show UAN verification status clearly

### AI Analysis Display
- [ ] Implement loading state with spinner
- [ ] Create score card component with color coding
- [ ] Create findings list components (positive/negative)
- [ ] Create red flags component with severity colors
- [ ] Create expandable analysis sections
- [ ] Display candidate type badge
- [ ] Show UAN verification note

### Staff Decision
- [ ] Create staff decision form
- [ ] Add approve/reject radio buttons
- [ ] Add remarks textarea
- [ ] Implement submit functionality

### API Integration
- [ ] Implement runAIValidation API call
- [ ] Implement getAIResults API call
- [ ] Implement submitDecision API call
- [ ] Handle file upload (multipart/form-data)
- [ ] Handle form data (application/x-www-form-urlencoded)

### Error Handling
- [ ] Handle no resume error
- [ ] Handle S3 download errors
- [ ] Handle API timeout errors
- [ ] Handle network errors
- [ ] Show appropriate error messages

### UI/UX
- [ ] Add success/error notifications
- [ ] Make responsive (mobile/tablet/desktop)
- [ ] Add accessibility features (ARIA labels)
- [ ] Add loading states for all async operations
- [ ] Test with sample data
- [ ] Handle edge cases (no resume, API errors, etc.)
- [ ] Add tooltips for UAN/PAN fields

---

## 🔧 Backend Resume Handling (Automatic)

**Important:** The UI doesn't need to handle S3 downloads. The backend does it automatically!

### How It Works:

1. **UI sends request** (with or without file)
2. **Backend checks**:
   - If file uploaded → use it
   - If no file → fetch `candidate.resumePath`
3. **Backend detects path type**:
   - If starts with `http://`, `https://`, or `s3://` → **S3 URL**
   - Else → **Local path**
4. **If S3 URL**:
   - Backend downloads from S3 automatically
   - Saves to temp file
   - Processes
   - Deletes temp file
5. **If Local path**:
   - Backend uses file directly

### What UI Needs to Do:

✅ **Just send these 4 fields** - backend handles everything else!

```javascript
// Option 1: With file upload
const formData = new FormData();
formData.append('verificationId', id);
formData.append('resume', file);        // ← Include file
formData.append('panNumber', pan);      // ← Optional
formData.append('hasUan', 'yes');       // ← Optional

// Option 2: Without file upload (use database resume)
const formData = new FormData();
formData.append('verificationId', id);
// NO resume file - backend auto-fetches from candidate.resumePath
formData.append('panNumber', pan);      // ← Optional
formData.append('hasUan', 'yes');       // ← Optional
```

**UI does NOT send:**
- ❌ Resume path/URL
- ❌ S3 bucket name
- ❌ File location

**Backend automatically:**
- ✅ Fetches `candidate.resumePath` from database
- ✅ Detects if it's S3 or local
- ✅ Downloads from S3 if needed

### Supported Resume Path Formats:

```javascript
// All these work automatically:
"https://my-bucket.s3.amazonaws.com/resumes/john.pdf"  // S3 HTTPS
"s3://my-bucket/resumes/john.pdf"                      // S3 protocol
"http://my-cdn.com/resumes/john.pdf"                   // HTTP URL
"/mnt/resumes/john.pdf"                                // Local path
```

---

## 📞 Support

For questions or clarifications, contact the backend team.

**API Base URL:** `https://your-api-domain.com`

**Authentication:** JWT token in Authorization header

**Resume Storage:** Supports both S3 and local file paths (automatic detection)

---

## 📝 Important Notes for UI Team

1. **Resume Upload is Optional** - If candidate already has resume in database, user can skip upload
2. **S3 Handling is Automatic** - Backend downloads from S3, UI doesn't need to worry about it
3. **Show Resume Status** - Display if resume is available and from where (S3/Local)
4. **UAN is Optional** - Can provide PAN (auto-check), manual yes/no, or skip entirely
5. **Loading Time** - AI analysis takes 10-15 seconds, show clear loading state
6. **Manual Review Required** - AI results are always PENDING until staff submits decision
7. **Score Color Coding** - Use provided color scheme for authenticity scores
8. **Red Flags** - Display with severity-based colors (HIGH=red, MEDIUM=orange, LOW=yellow)

---

**Document Version:** 2.0  
**Last Updated:** December 2, 2024  
**Feature:** AI CV Authenticity Validation with S3 Support
