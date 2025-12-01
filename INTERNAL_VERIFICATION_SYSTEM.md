# Internal Verification System

## Overview
The internal verification system provides manual and AI-assisted verification checks that are performed internally by the BGV team rather than through external APIs. These checks require manual review and approval through the UI.

## Available Internal Verification Checks

### 1. Address Verification (`address_verification`)
- **Type**: Manual verification
- **Purpose**: Verify candidate's residential address
- **Required Fields**: `address`
- **Process**: 
  - Check returns PENDING status initially
  - Staff manually verifies address through documents/site visit
  - Status updated to COMPLETED/FAILED through UI
- **Data Available**: address, district, state, pincode

### 2. Education Check Manual (`education_check_manual`)
- **Type**: Manual offline verification
- **Purpose**: Verify education credentials through manual research
- **Required Fields**: `firstName`, `lastName`
- **Process**:
  - Check returns PENDING status initially
  - Staff manually contacts institutions or verifies through official channels
  - Status updated to COMPLETED/FAILED through UI
- **Instructions**: Manually verify education credentials through institution contact or online verification

### 3. Education Check AI (`education_check_ai`)
- **Type**: AI-assisted verification
- **Purpose**: Verify education certificates using OCR and LLM validation
- **Required Fields**: `educationCertificatePath`
- **Process**:
  - Upload education certificate (PDF/DOCX)
  - System extracts text using OCR/PDF parsing
  - LLM validates certificate authenticity and details
  - Returns COMPLETED/FAILED automatically
- **Validation Checks**:
  - Valid institution name and accreditation
  - Proper certificate format and structure
  - Consistent dates and academic years
  - Authentic looking signatures and seals
  - Matching candidate name
  - Valid degree/course information

### 4. Supervisory Check (`supervisory_check`)
- **Type**: Manual phone verification
- **Purpose**: Verify employment through phone call to previous organization
- **Required Fields**: `firstName`, `lastName`
- **Process**:
  - Check returns PENDING status initially
  - Staff makes phone call to candidate's previous organization
  - Status updated to COMPLETED/FAILED through UI
- **Instructions**: Contact candidate's previous organization for employment verification via phone call

### 5. Employment History Manual (`employment_history_manual`)
- **Type**: Manual offline verification
- **Purpose**: Verify employment history through manual research
- **Required Fields**: `firstName`, `lastName`
- **Process**:
  - Check returns PENDING status initially
  - Staff manually verifies through previous employers, documents, or references
  - Status updated to COMPLETED/FAILED through UI
- **Instructions**: Manually verify employment history through previous employers, documents, or references

## API Endpoints

### 1. Update Internal Verification
```
POST /secure/updateInternalVerification
```

**Purpose**: Manually update the status of internal verification checks

**Request Body**:
```json
{
  "verificationId": "verification_object_id",
  "stage": "primary|secondary|final",
  "checkName": "address_verification|education_check_manual|supervisory_check|employment_history_manual",
  "status": "COMPLETED|FAILED",
  "remarks": "Manual verification notes and findings",
  "attachments": ["optional_file_urls"]
}
```

**Response**:
```json
{
  "message": "Internal verification updated successfully",
  "verificationId": "verification_id",
  "stage": "primary",
  "checkName": "address_verification",
  "status": "COMPLETED",
  "updatedBy": "user@example.com",
  "updatedAt": "2024-01-01T10:00:00Z"
}
```

### 2. Get Internal Verification Details
```
GET /secure/getInternalVerificationDetails/{verificationId}
```

**Purpose**: Get details of internal verification checks for manual review

**Response**:
```json
{
  "verificationId": "verification_id",
  "candidateId": "candidate_id",
  "candidateDetails": {
    "name": "John Doe",
    "email": "john@example.com",
    "phone": "+1234567890",
    "address": "123 Main St, City, State",
    "district": "District Name",
    "state": "State Name",
    "pincode": "123456"
  },
  "organizationId": "org_id",
  "organizationName": "Organization Name",
  "overallStatus": "IN_PROGRESS",
  "currentStage": "primary",
  "internalVerifications": {
    "primary": [
      {
        "checkName": "address_verification",
        "status": "PENDING",
        "remarks": "",
        "submittedAt": null,
        "updatedBy": null,
        "attachments": [],
        "requiresManualVerification": true
      }
    ]
  }
}
```

### 3. Upload Education Certificate
```
POST /secure/uploadEducationCertificate
```

**Purpose**: Upload education certificate for AI verification

**Request**: Multipart form data
- `candidateId`: Candidate ID
- `file`: PDF or DOCX certificate file

**Response**:
```json
{
  "message": "Education certificate uploaded successfully",
  "candidateId": "candidate_id",
  "filename": "generated_filename.pdf",
  "filePath": "uploads/education_certificates/filename.pdf"
}
```

## Integration with Existing System

### 1. Adding Internal Checks to Verification Stages
Internal verification checks can be added to any verification stage (primary, secondary, final) just like external API checks:

```json
{
  "candidateId": "candidate_id",
  "organizationId": "org_id",
  "stages": {
    "primary": [
      "pan_verification",
      "address_verification",
      "education_check_manual"
    ]
  }
}
```

### 2. Check Status Flow
- **External API Checks**: NOT_STARTED → IN_PROGRESS → COMPLETED/FAILED
- **Internal Manual Checks**: NOT_STARTED → PENDING → COMPLETED/FAILED (via UI update)
- **Internal AI Checks**: NOT_STARTED → IN_PROGRESS → COMPLETED/FAILED (automatic)

### 3. Role-Based Access Control
All internal verification endpoints follow the same role-based access control as existing verification endpoints:

- **SUPER_ADMIN/SUPER_SPOC**: Full access to all verifications
- **BGV SPOC**: Full access to all verifications
- **SUPER_ADMIN_HELPER**: Access to assigned organizations only
- **ORG_HR/SPOC**: Access to own organization only
- **HELPER**: Access to own candidates and assigned verifications only

## UI Integration Guidelines

### 1. Manual Verification Interface
For manual checks (address, education manual, supervisory, employment history):
- Display candidate information and check requirements
- Provide text area for verification notes/remarks
- Allow file attachments for supporting documents
- Provide COMPLETED/FAILED status buttons
- Show verification history and timestamps

### 2. AI Verification Interface
For AI checks (education AI):
- Provide file upload interface for certificates
- Display AI analysis results
- Show extracted text and validation details
- Allow manual override if needed
- Display confidence scores and identified issues

### 3. Status Indicators
- **PENDING**: Yellow/Orange indicator - requires manual action
- **IN_PROGRESS**: Blue indicator - processing
- **COMPLETED**: Green indicator - verified successfully
- **FAILED**: Red indicator - verification failed

## File Storage
Education certificates are stored in `uploads/education_certificates/` directory with naming pattern:
`{candidateId}_education_cert_{timestamp}.{extension}`

## Error Handling
- Invalid verification IDs return 400 Bad Request
- Unauthorized access returns 403 Forbidden
- Missing verifications/candidates return 404 Not Found
- Invalid file types for certificates return 400 Bad Request
- AI processing errors are captured and returned as FAILED status

## Logging
All internal verification activities are logged with:
- User email and role
- Action performed
- Verification/candidate details
- Timestamp
- Success/failure status