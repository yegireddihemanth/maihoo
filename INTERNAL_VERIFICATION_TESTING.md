# Internal Verification System Testing Guide

## Quick Test Scenarios

### 1. Test Internal Verification Checks in Stage Creation

**Create verification with internal checks:**
```bash
POST /secure/initiateStageVerification
{
  "candidateId": "candidate_id_here",
  "organizationId": "org_id_here",
  "stages": {
    "primary": [
      "address_verification",
      "education_check_manual",
      "supervisory_check"
    ]
  }
}
```

**Expected Result**: 
- Verification created with PENDING status for all internal checks
- Checks show `requiresManualVerification: true`

### 2. Test Manual Status Update

**Update address verification:**
```bash
POST /secure/updateInternalVerification
{
  "verificationId": "verification_id_here",
  "stage": "primary",
  "checkName": "address_verification",
  "status": "COMPLETED",
  "remarks": "Address verified through utility bill and site visit. Confirmed residential address matches records."
}
```

**Expected Result**:
- Check status changes from PENDING to COMPLETED
- Remarks and timestamp are saved
- updatedBy field shows current user email

### 3. Test Education Certificate Upload and AI Verification

**Step 1 - Upload certificate:**
```bash
POST /secure/uploadEducationCertificate
Form Data:
- candidateId: "candidate_id_here"
- file: [PDF/DOCX certificate file]
```

**Step 2 - Add AI education check:**
```bash
POST /secure/initiateStageVerification
{
  "candidateId": "candidate_id_here",
  "organizationId": "org_id_here",
  "stages": {
    "secondary": [
      "education_check_ai"
    ]
  }
}
```

**Step 3 - Run the stage:**
```bash
POST /secure/runStage
{
  "verificationId": "verification_id_here",
  "stage": "secondary"
}
```

**Expected Result**:
- Certificate uploaded successfully
- AI check processes automatically
- Returns COMPLETED/FAILED based on LLM analysis
- Shows extracted text and validation details

### 4. Test Internal Verification Details Retrieval

**Get verification details:**
```bash
GET /secure/getInternalVerificationDetails/verification_id_here
```

**Expected Result**:
- Returns candidate details
- Shows all internal verification checks by stage
- Displays current status and manual verification requirements
- Shows remarks and update history

### 5. Test Role-Based Access Control

**Test as different roles:**

**SUPER_ADMIN**: Should access all verifications
**ORG_HR**: Should only access own organization verifications  
**HELPER**: Should only access own candidates and assigned verifications

**Test unauthorized access:**
```bash
# Helper trying to update verification from different org
POST /secure/updateInternalVerification
{
  "verificationId": "different_org_verification_id",
  "stage": "primary",
  "checkName": "address_verification",
  "status": "COMPLETED"
}
```

**Expected Result**: 403 Forbidden error

## Test Data Setup

### Sample Candidate with Required Fields
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "phone": "+1234567890",
  "address": "123 Main Street, Apartment 4B",
  "district": "Central District",
  "state": "California",
  "pincode": "90210",
  "organizationId": "org_id_here"
}
```

### Sample Internal Verification Stages
```json
{
  "primary": [
    "address_verification",
    "education_check_manual"
  ],
  "secondary": [
    "education_check_ai",
    "supervisory_check"
  ],
  "final": [
    "employment_history_manual"
  ]
}
```

## Error Testing Scenarios

### 1. Invalid Check Names
```bash
POST /secure/updateInternalVerification
{
  "verificationId": "valid_id",
  "stage": "primary",
  "checkName": "invalid_check_name",
  "status": "COMPLETED"
}
```
**Expected**: 400 Bad Request - "Check invalid_check_name is not an internal verification check"

### 2. Invalid Status Values
```bash
POST /secure/updateInternalVerification
{
  "verificationId": "valid_id",
  "stage": "primary", 
  "checkName": "address_verification",
  "status": "INVALID_STATUS"
}
```
**Expected**: 400 Bad Request - "Status must be COMPLETED or FAILED"

### 3. Missing Education Certificate
```bash
POST /secure/initiateStageVerification
{
  "stages": {
    "primary": ["education_check_ai"]
  }
}
```
**Expected**: Check should fail with "Education certificate not uploaded"

### 4. Unsupported File Types
```bash
POST /secure/uploadEducationCertificate
Form Data:
- candidateId: "valid_id"
- file: [.txt or .jpg file]
```
**Expected**: 400 Bad Request - "Only PDF and DOCX files are allowed"

## Performance Testing

### 1. AI Processing Time
- Upload various sized PDF/DOCX files (1MB, 5MB, 10MB)
- Measure processing time for text extraction and LLM validation
- Verify timeout handling for large files

### 2. Concurrent Updates
- Multiple users updating different internal checks simultaneously
- Verify no race conditions or data corruption
- Test database locking and consistency

## Integration Testing

### 1. Full Verification Flow
1. Create candidate
2. Upload education certificate
3. Initiate verification with mixed internal/external checks
4. Run external checks (should complete automatically)
5. Manually update internal checks through UI
6. Verify overall verification status updates correctly

### 2. Stage Progression
1. Complete primary stage with internal checks
2. Initiate secondary stage
3. Verify stage progression rules still work
4. Ensure no duplicate checks across stages

## UI Testing Checklist

- [ ] Internal checks show PENDING status with manual action required
- [ ] Update buttons are enabled for authorized users only
- [ ] Remarks text area saves and displays correctly
- [ ] File upload works for education certificates
- [ ] AI analysis results display properly
- [ ] Status indicators show correct colors and states
- [ ] Verification history shows all updates with timestamps
- [ ] Role-based UI elements hide/show appropriately

## API Response Validation

Verify all responses include:
- [ ] Correct HTTP status codes
- [ ] Proper JSON structure
- [ ] Required fields present
- [ ] Timestamps in ISO format
- [ ] ObjectIds as strings
- [ ] Error messages are descriptive
- [ ] Success messages are clear