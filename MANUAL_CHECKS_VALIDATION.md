# 📋 Manual Checks - Required Data Validation

## **Overview**

Manual checks now require specific data to be present in the candidate document BEFORE they can be initiated. This ensures verification teams have all necessary information.

---

## **Manual Checks & Required Data**

### **1. supervisory_check_1**
**Required Field:** `supervisoryCheck1`

**Structure:**
```json
{
  "supervisoryCheck1": {
    "name": "Jane Smith",
    "phone": "+91-9876543210",
    "email": "jane@previouscompany.com",
    "relationship": "Former Manager",
    "company": "Previous Company Name"
  }
}
```

---

### **2. supervisory_check_2**
**Required Field:** `supervisoryCheck2`

**Structure:**
```json
{
  "supervisoryCheck2": {
    "name": "John Doe",
    "phone": "+91-1234567890",
    "email": "john@company.com",
    "relationship": "Former Colleague",
    "company": "Previous Company Name"
  }
}
```

---

### **3. employment_history_manual**
**Required Field:** `employmentHistory1`

**Structure:**
```json
{
  "employmentHistory1": {
    "company": "ABC Corporation",
    "hrContact": "+91-9876543210",
    "hrEmail": "hr@abc.com",
    "address": "123 Business Park, City, State - 123456",
    "relievingLetterUrl": "https://s3.../relieving_letter.pdf",
    "joiningDate": "2020-01-15",
    "relievingDate": "2023-06-30"
  }
}
```

---

### **4. employment_history_manual_2**
**Required Field:** `employmentHistory2`

**Structure:**
```json
{
  "employmentHistory2": {
    "company": "XYZ Ltd",
    "hrContact": "+91-1234567890",
    "hrEmail": "hr@xyz.com",
    "address": "456 Tech Park, City, State - 654321",
    "relievingLetterUrl": "https://s3.../relieving_letter_2.pdf",
    "joiningDate": "2018-03-01",
    "relievingDate": "2019-12-31"
  }
}
```

---

### **5. employment_check_2**
**Required Field:** `employmentHistory2`

Same structure as `employment_history_manual_2`

---

### **6. education_check_manual**
**Required Field:** `educationCheck`

**Structure:**
```json
{
  "educationCheck": {
    "certificateUrl": "https://s3.../degree_certificate.pdf",
    "universityName": "ABC University",
    "universityContact": "+91-9876543210",
    "universityEmail": "verification@university.edu",
    "universityAddress": "123 University Road, City, State - 123456",
    "degree": "Bachelor of Technology",
    "yearOfPassing": "2020"
  }
}
```

---

## **Validation Flow**

### **When Adding Candidate:**
```
POST /secure/addCandidate
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john@example.com",
  // ... other fields
  
  // ✅ Add manual check data
  "supervisoryCheck1": {...},
  "employmentHistory1": {...},
  "educationCheck": {...}
}
```

### **When Initiating Verification:**
```
POST /secure/initiateStageVerification
{
  "candidateId": "507f...",
  "organizationId": "507f...",
  "stages": {
    "primary": [
      "pan_verification",
      "supervisory_check_1",  // ✅ Will validate supervisoryCheck1 exists
      "education_check_manual"  // ✅ Will validate educationCheck exists
    ]
  }
}
```

**If data is missing:**
```json
{
  "detail": {
    "error": "Missing required data for checks",
    "missingData": [
      {
        "check": "supervisory_check_1",
        "missingField": "supervisoryCheck1 (requires name and phone)",
        "message": "Check 'supervisory_check_1' requires 'supervisoryCheck1 (requires name and phone)' in candidate data"
      }
    ],
    "action": "Please update candidate information before initiating these checks",
    "candidateId": "507f..."
  }
}
```

---

## **Error Handling**

### **Missing Field Error:**
```json
{
  "detail": {
    "error": "Missing required data for checks",
    "missingData": [
      {
        "check": "education_check_manual",
        "missingField": "educationCheck (requires certificateUrl and universityContact)",
        "message": "Check 'education_check_manual' requires 'educationCheck (requires certificateUrl and universityContact)' in candidate data"
      }
    ],
    "action": "Please update candidate information before initiating these checks",
    "candidateId": "6935b10cddc33ed7592426ba"
  }
}
```

**Solution:** Update candidate with required data:
```
PUT /secure/modifyCandidate
{
  "candidateId": "6935b10cddc33ed7592426ba",
  "educationCheck": {
    "certificateUrl": "https://s3.../cert.pdf",
    "universityContact": "+91-1234567890",
    "universityName": "ABC University"
  }
}
```

---

## **Frontend Integration**

### **Add Candidate Form:**
```jsx
// Show conditional fields based on selected checks
{selectedChecks.includes('supervisory_check_1') && (
  <div>
    <h3>Supervisory Check 1 Details</h3>
    <input name="supervisoryCheck1.name" placeholder="Supervisor Name" />
    <input name="supervisoryCheck1.phone" placeholder="Phone" />
    <input name="supervisoryCheck1.email" placeholder="Email" />
    <input name="supervisoryCheck1.relationship" placeholder="Relationship" />
  </div>
)}

{selectedChecks.includes('education_check_manual') && (
  <div>
    <h3>Education Verification Details</h3>
    <FileUpload name="educationCertificate" />
    <input name="educationCheck.universityName" placeholder="University" />
    <input name="educationCheck.universityContact" placeholder="Contact" />
  </div>
)}
```

### **Initiate Verification:**
```javascript
try {
  await initiateStageVerification({
    candidateId,
    organizationId,
    stages: { primary: selectedChecks }
  });
} catch (error) {
  if (error.detail?.missingData) {
    // Show missing data errors
    error.detail.missingData.forEach(item => {
      alert(`${item.check}: ${item.message}`);
    });
    
    // Redirect to edit candidate page
    router.push(`/candidates/edit/${candidateId}`);
  }
}
```

---

## **Benefits**

✅ **Early Validation** - Catch missing data before verification starts  
✅ **Clear Errors** - Specific messages about what's missing  
✅ **Better UX** - Users know exactly what to add  
✅ **No Broken Flow** - Verification won't start with incomplete data  
✅ **Email Ready** - All data available when sending to verification team  

---

## **Next Steps**

After validation is working:
1. **Email Notifications** - Send manual check details to SUPER_ADMIN/SUPER_SPOC
2. **Submission Endpoint** - Allow verification team to submit results
3. **Status Updates** - Update check status from PENDING to COMPLETED

---

**Validation is now active! Test by initiating checks without required data.**
