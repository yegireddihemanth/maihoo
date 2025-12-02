# S3 Resume Upload - Integration Guide

## ✅ What Was Implemented

The `/secure/addCandidate` endpoint now supports **automatic resume upload to S3**.

---

## 🔧 Configuration

### AWS S3 Credentials (in `.env`):
```
AWS_ACCESS_KEY_ID=AKIAX3AM3BQY4WRNIIISM
AWS_SECRET_ACCESS_KEY=f0mCDaRGh9zo3Yt0xtKKUIdZPHKL9MXBmJRykU/x
AWS_S3_BUCKET_NAME=maihoofiles
AWS_REGION=ap-south-2
```

### S3 Bucket Structure:
```
maihoofiles/
├── TechCorp/
│   ├── John_Doe/
│   │   └── John_Doe_resume.pdf
│   ├── Jane_Smith/
│   │   └── Jane_Smith_resume.pdf
├── AnotherOrg/
│   ├── Bob_Johnson/
│   │   └── Bob_Johnson_resume.pdf
```

**Pattern:** `{organizationName}/{firstName}_{lastName}/{firstName}_{lastName}_resume.{ext}`

---

## 📡 API Endpoint

### POST /secure/addCandidate

**Changed from:** `application/json` (Body)  
**Changed to:** `multipart/form-data` (Form)

**Request:**
```
POST /secure/addCandidate
Authorization: Bearer {token}
Content-Type: multipart/form-data

Fields:
- firstName: string (required)
- middleName: string (optional)
- lastName: string (required)
- phone: string (required)
- aadhaarNumber: string (required)
- panNumber: string (required)
- address: string (required)
- email: string (required)
- fatherName: string (required)
- dob: string (required)
- gender: string (required)
- uanNumber: string (optional)
- district: string (required)
- state: string (required)
- pincode: string (required)
- organizationId: string (optional - depends on role)
- resume: file (optional - PDF/DOCX)
```

**Response:**
```json
{
  "message": "Candidate added successfully with resume uploaded to S3",
  "candidate": {
    "_id": "674a1234567890abcdef1234",
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@example.com",
    "resumePath": "https://maihoofiles.s3.ap-south-2.amazonaws.com/TechCorp/John_Doe/John_Doe_resume.pdf",
    ...
  },
  "resumeUploaded": true,
  "resumePath": "https://maihoofiles.s3.ap-south-2.amazonaws.com/TechCorp/John_Doe/John_Doe_resume.pdf",
  "s3UploadError": null
}
```

---

## 🎯 How It Works

### With Resume Upload:
```
1. User submits candidate form with resume file
   ↓
2. Backend validates candidate data
   ↓
3. Backend uploads resume to S3:
   - Folder: {orgName}/{firstName}_{lastName}/
   - File: {firstName}_{lastName}_resume.pdf
   ↓
4. Backend gets S3 URL
   ↓
5. Backend saves candidate with resumePath field
   ↓
6. Returns success with S3 URL
```

### Without Resume Upload:
```
1. User submits candidate form without resume
   ↓
2. Backend validates candidate data
   ↓
3. Backend saves candidate without resumePath
   ↓
4. Returns success (resumePath = null)
```

---

## 🔗 Integration with AI CV Validation

The AI CV Validation endpoint automatically detects S3 URLs:

```javascript
// When running AI validation
POST /secure/ai_cv_validation
{
  verificationId: "123",
  // No resume file needed
}

// Backend automatically:
// 1. Gets candidate.resumePath from database
// 2. Detects it's S3 URL
// 3. Downloads from S3
// 4. Processes for AI validation
```

**S3 URL Example:**
```
https://maihoofiles.s3.ap-south-2.amazonaws.com/TechCorp/John_Doe/John_Doe_resume.pdf
```

---

## 📝 Frontend Integration

### Example: Add Candidate with Resume

```javascript
async function addCandidateWithResume(candidateData, resumeFile) {
  const formData = new FormData();
  
  // Add all candidate fields
  formData.append('firstName', candidateData.firstName);
  formData.append('lastName', candidateData.lastName);
  formData.append('phone', candidateData.phone);
  formData.append('aadhaarNumber', candidateData.aadhaarNumber);
  formData.append('panNumber', candidateData.panNumber);
  formData.append('address', candidateData.address);
  formData.append('email', candidateData.email);
  formData.append('fatherName', candidateData.fatherName);
  formData.append('dob', candidateData.dob);
  formData.append('gender', candidateData.gender);
  formData.append('district', candidateData.district);
  formData.append('state', candidateData.state);
  formData.append('pincode', candidateData.pincode);
  
  // Optional fields
  if (candidateData.middleName) {
    formData.append('middleName', candidateData.middleName);
  }
  if (candidateData.uanNumber) {
    formData.append('uanNumber', candidateData.uanNumber);
  }
  if (candidateData.organizationId) {
    formData.append('organizationId', candidateData.organizationId);
  }
  
  // Add resume file (optional)
  if (resumeFile) {
    formData.append('resume', resumeFile);
  }
  
  const response = await fetch('/secure/addCandidate', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`
      // Don't set Content-Type - browser sets it automatically for multipart/form-data
    },
    body: formData
  });
  
  return await response.json();
}
```

### Example: Usage

```javascript
// With resume
const result = await addCandidateWithResume(
  {
    firstName: 'John',
    lastName: 'Doe',
    email: 'john@example.com',
    phone: '9876543210',
    // ... other fields
  },
  resumeFileObject  // File from <input type="file">
);

console.log(result.resumePath);
// Output: https://maihoofiles.s3.ap-south-2.amazonaws.com/TechCorp/John_Doe/John_Doe_resume.pdf

// Without resume
const result = await addCandidateWithResume(
  {
    firstName: 'Jane',
    lastName: 'Smith',
    // ... other fields
  },
  null  // No resume
);

console.log(result.resumePath);
// Output: null
```

---

## ⚠️ Error Handling

### S3 Upload Fails:
```json
{
  "message": "Candidate added successfully (Warning: Resume upload failed - S3 connection error)",
  "candidate": { ... },
  "resumeUploaded": false,
  "resumePath": null,
  "s3UploadError": "Failed to upload to S3: Connection timeout"
}
```

**Note:** Candidate is still created even if S3 upload fails. Resume can be uploaded later.

### Invalid File Type:
```json
{
  "detail": "Only PDF/DOCX files are supported for resume"
}
```

---

## 🔐 S3 Permissions Required

Your S3 bucket needs these permissions:
- `s3:PutObject` - Upload files
- `s3:GetObject` - Download files (for AI validation)
- `s3:ListBucket` - List files (optional)

---

## 🧪 Testing

### Test 1: Add Candidate with Resume
```bash
curl -X POST http://localhost:8000/secure/addCandidate \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "firstName=John" \
  -F "lastName=Doe" \
  -F "email=john@example.com" \
  -F "phone=9876543210" \
  -F "aadhaarNumber=123456789012" \
  -F "panNumber=ABCDE1234F" \
  -F "address=123 Main St" \
  -F "fatherName=John Sr" \
  -F "dob=1990-01-01" \
  -F "gender=Male" \
  -F "district=Hyderabad" \
  -F "state=Telangana" \
  -F "pincode=500001" \
  -F "resume=@/path/to/resume.pdf"
```

### Test 2: Add Candidate without Resume
```bash
curl -X POST http://localhost:8000/secure/addCandidate \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "firstName=Jane" \
  -F "lastName=Smith" \
  -F "email=jane@example.com" \
  ... (other fields)
  # No resume field
```

---

## 📊 Database Schema Update

### Candidate Document:
```json
{
  "_id": "674a1234567890abcdef1234",
  "firstName": "John",
  "lastName": "Doe",
  "email": "john@example.com",
  "phone": "9876543210",
  "resumePath": "https://maihoofiles.s3.ap-south-2.amazonaws.com/TechCorp/John_Doe/John_Doe_resume.pdf",
  // ↑ NEW FIELD - S3 URL or null
  ...
}
```

---

## ✅ Benefits

1. **Centralized Storage** - All resumes in one S3 bucket
2. **Organized Structure** - Folders by org and candidate name
3. **Scalable** - S3 handles unlimited files
4. **Automatic Integration** - AI CV validation works automatically
5. **No Local Storage** - No need for `/mnt/resumes/` folder
6. **Accessible** - Resumes accessible via HTTPS URL
7. **Backup** - S3 provides automatic backup and versioning

---

## 🚀 Next Steps

1. ✅ S3 credentials configured
2. ✅ boto3 installed
3. ✅ Upload function implemented
4. ✅ addCandidate endpoint updated
5. ✅ AI CV validation supports S3 URLs
6. ⏳ Update frontend to use multipart/form-data
7. ⏳ Test with real resume uploads
8. ⏳ Configure S3 bucket CORS if needed

---

**Document Version:** 1.0  
**Last Updated:** December 2, 2024  
**Feature:** S3 Resume Upload Integration
