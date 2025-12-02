# Complete UI Implementation Guide - All Verification Types

## 📋 Table of Contents
1. [All Available Verification Types](#all-available-verification-types)
2. [API Endpoints](#api-endpoints)
3. [UI Components](#ui-components)
4. [Implementation Steps](#implementation-steps)
5. [Code Examples](#code-examples)

---

## 🎯 All Available Verification Types

### API-Based Checks (Automatic via Surepass)
| Check Name | Type | Required Fields | Time | Cost |
|------------|------|----------------|------|------|
| `pan_verification` | API | panNumber | 2-3s | ₹5 |
| `aadhaar_verification` | API | aadhaarNumber | 2-3s | ₹5 |
| `pan_aadhaar_seeding` | API | panNumber, aadhaarNumber | 3-4s | ₹8 |
| `employment_history` | API | uanNumber | 5-8s | ₹15 |
| `verify_pan_to_uan` | API | panNumber | 3-4s | ₹10 |
| `credit_report` | API | phone, panNumber, firstName, lastName | 10-15s | ₹50 |
| `court_record` | API | firstName, lastName, address | 8-12s | ₹30 |

### Manual Checks (Human Verification)
| Check Name | Type | Required Fields | Time | Cost |
|------------|------|----------------|------|------|
| `address_verification` | Manual | address, district, state, pincode | 1-2 days | ₹100 |
| `education_check_manual` | Manual | firstName, lastName | 1-3 days | ₹100 |
| `supervisory_check` | Manual | firstName, lastName, phone | 1-2 days | ₹80 |
| `employment_history_manual` | Manual | firstName, lastName | 2-3 days | ₹120 |

### AI-Powered Checks (Automatic via LLaMA)
| Check Name | Type | Required Fields | Time | Cost |
|------------|------|----------------|------|------|
| `resume_validation` | AI | resumePath | 5-10s | Free |
| `education_check_manual` | Manual | firstName, lastName | Manual | Free |

---

## 🔌 API Endpoints

### 1. Initiate Verification
```
POST /secure/initiateStageVerification
```

**Purpose:** Create verification with selected checks

**Body:**
```json
{
  "candidateId": "cand_123",
  "organizationId": "org_456",
  "stages": {
    "primary": [
      "pan_verification",           // API
      "address_verification",       // Manual
      "resume_validation"           // AI
    ]
  }
}
```

**Response:**
```json
{
  "verificationId": "ver_789",
  "stages": {
    "primary": [
      {"check": "pan_verification", "status": "PENDING"},
      {"check": "address_verification", "status": "PENDING"},
      {"check": "resume_validation", "status": "PENDING"}
    ]
  }
}
```

---

### 2. Run API/AI Checks
```
POST /secure/runStage
```

**Purpose:** Execute all API and AI checks automatically

**Body:**
```json
{
  "verificationId": "ver_789",
  "stage": "primary"
}
```

**What Happens:**
- ✅ Runs all API checks (PAN, Aadhaar, etc.)
- ✅ Runs all API checks only (AI checks removed)
- ⏳ Skips manual checks (leaves as PENDING)

**Response:**
```json
{
  "message": "Stage completed",
  "stage": "primary"
}
```

---

### 3. Get Verification Status
```
GET /secure/getVerificationById/{verificationId}
```

**Purpose:** Check current status and progress

**Response:**
```json
{
  "verificationId": "ver_789",
  "currentStage": "primary",
  "overallStatus": "IN_PROGRESS",
  "stages": {
    "primary": [
      {
        "check": "pan_verification",
        "status": "COMPLETED",
        "remarks": "PAN verified successfully"
      },
      {
        "check": "address_verification",
        "status": "PENDING",
        "remarks": null
      }
    ]
  },
  "progress": {
    "totalChecks": 3,
    "completedChecks": 1,
    "completionPercentage": 33
  }
}
```

---

### 4. Update Manual Check
```
POST /secure/updateInternalVerification
```

**Purpose:** Mark manual check as complete

**Body:**
```json
{
  "verificationId": "ver_789",
  "stage": "primary",
  "checkName": "address_verification",
  "status": "COMPLETED",
  "remarks": "Visited address on Jan 16. Confirmed with utility bill."
}
```

**Response:**
```json
{
  "check": "address_verification",
  "status": "COMPLETED",
  "stageCompleted": false,
  "canProceed": true
}
```

---

### 5. Get All Verifications
```
GET /secure/getVerificationsByOrganization?organizationId={orgId}
```

**Purpose:** List all verifications for an organization

**Response:**
```json
{
  "verifications": [
    {
      "verificationId": "ver_789",
      "candidateName": "John Doe",
      "currentStage": "primary",
      "completionPercentage": 66,
      "totalChecks": 3,
      "completedChecks": 2
    }
  ]
}
```

---

## 🎨 UI Components

### Component 1: Check Selection Form

**Purpose:** Let user select which checks to run

```jsx
function CheckSelectionForm({ candidateId, onSubmit }) {
  const [selectedChecks, setSelectedChecks] = useState([]);
  
  const availableChecks = {
    api: [
      { id: 'pan_verification', name: 'PAN Verification', cost: 5, time: '2-3s' },
      { id: 'aadhaar_verification', name: 'Aadhaar Verification', cost: 5, time: '2-3s' },
      { id: 'employment_history', name: 'Employment History', cost: 15, time: '5-8s' },
      { id: 'credit_report', name: 'Credit Report', cost: 50, time: '10-15s' },
      { id: 'court_record', name: 'Court Record', cost: 30, time: '8-12s' }
    ],
    manual: [
      { id: 'address_verification', name: 'Address Verification', cost: 100, time: '1-2 days' },
      { id: 'education_check_manual', name: 'Education Check', cost: 100, time: '1-3 days' },
      { id: 'supervisory_check', name: 'Supervisory Check', cost: 80, time: '1-2 days' }
    ],
    ai: [
      { id: 'resume_validation', name: 'Resume Validation', cost: 0, time: '5-10s' },
      // AI checks removed - new approach to be implemented
    ]
  };
  
  const handleCheckToggle = (checkId) => {
    setSelectedChecks(prev => 
      prev.includes(checkId) 
        ? prev.filter(id => id !== checkId)
        : [...prev, checkId]
    );
  };
  
  const totalCost = selectedChecks.reduce((sum, checkId) => {
    const check = [...availableChecks.api, ...availableChecks.manual, ...availableChecks.ai]
      .find(c => c.id === checkId);
    return sum + (check?.cost || 0);
  }, 0);
  
  return (
    <div className="check-selection-form">
      <h2>Select Verification Checks</h2>
      
      {/* API Checks */}
      <div className="check-category">
        <h3>🔌 API Checks (Automatic)</h3>
        {availableChecks.api.map(check => (
          <label key={check.id} className="check-item">
            <input
              type="checkbox"
              checked={selectedChecks.includes(check.id)}
              onChange={() => handleCheckToggle(check.id)}
            />
            <span className="check-name">{check.name}</span>
            <span className="check-cost">₹{check.cost}</span>
            <span className="check-time">{check.time}</span>
          </label>
        ))}
      </div>
      
      {/* Manual Checks */}
      <div className="check-category">
        <h3>👤 Manual Checks (Human Verification)</h3>
        {availableChecks.manual.map(check => (
          <label key={check.id} className="check-item">
            <input
              type="checkbox"
              checked={selectedChecks.includes(check.id)}
              onChange={() => handleCheckToggle(check.id)}
            />
            <span className="check-name">{check.name}</span>
            <span className="check-cost">₹{check.cost}</span>
            <span className="check-time">{check.time}</span>
          </label>
        ))}
      </div>
      
      {/* AI Checks */}
      <div className="check-category">
        <h3>🤖 AI Checks (Automatic)</h3>
        {availableChecks.ai.map(check => (
          <label key={check.id} className="check-item">
            <input
              type="checkbox"
              checked={selectedChecks.includes(check.id)}
              onChange={() => handleCheckToggle(check.id)}
            />
            <span className="check-name">{check.name}</span>
            <span className="check-cost">Free</span>
            <span className="check-time">{check.time}</span>
          </label>
        ))}
      </div>
      
      <div className="summary">
        <p>Total Checks: {selectedChecks.length}</p>
        <p>Total Cost: ₹{totalCost}</p>
        <button onClick={() => onSubmit(selectedChecks)}>
          Start Verification
        </button>
      </div>
    </div>
  );
}
```

---

### Component 2: Verification Detail View

**Purpose:** Show all checks with status and progress

```jsx
function VerificationDetail({ verificationId }) {
  const [verification, setVerification] = useState(null);
  const [selectedCheck, setSelectedCheck] = useState(null);
  
  useEffect(() => {
    loadVerification();
    // Poll every 10 seconds for updates
    const interval = setInterval(loadVerification, 10000);
    return () => clearInterval(interval);
  }, [verificationId]);
  
  const loadVerification = async () => {
    const response = await fetch(
      `/secure/getVerificationById/${verificationId}`,
      { headers: { 'Authorization': `Bearer ${token}` } }
    );
    const data = await response.json();
    setVerification(data);
  };
  
  const handleRunAPIChecks = async () => {
    await fetch('/secure/runStage', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        verificationId,
        stage: verification.currentStage
      })
    });
    
    // Refresh after 5 seconds
    setTimeout(loadVerification, 5000);
  };
  
  const getCheckIcon = (status) => {
    switch(status) {
      case 'COMPLETED': return '✅';
      case 'FAILED': return '❌';
      case 'IN_PROGRESS': return '⏳';
      case 'PENDING': return '⏸️';
      default: return '⏸️';
    }
  };
  
  const getCheckType = (checkName) => {
    const apiChecks = ['pan_verification', 'aadhaar_verification', 'employment_history', 'credit_report', 'court_record'];
    const aiChecks = []; // AI checks removed
    
    if (apiChecks.includes(checkName)) return 'API';
    if (aiChecks.includes(checkName)) return 'AI';
    return 'Manual';
  };
  
  if (!verification) return <div>Loading...</div>;
  
  const checks = verification.stages[verification.currentStage] || [];
  const hasAPIChecks = checks.some(c => getCheckType(c.check) === 'API' && c.status === 'PENDING');
  const hasManualChecks = checks.some(c => getCheckType(c.check) === 'Manual' && c.status === 'PENDING');
  
  return (
    <div className="verification-detail">
      <div className="header">
        <h2>{verification.candidateName}</h2>
        <div className="progress">
          <div className="progress-bar">
            <div 
              className="progress-fill" 
              style={{ width: `${verification.progress.completionPercentage}%` }}
            />
          </div>
          <span>{verification.progress.completionPercentage}% Complete</span>
          <span>({verification.progress.completedChecks}/{verification.progress.totalChecks})</span>
        </div>
      </div>
      
      {hasAPIChecks && (
        <button onClick={handleRunAPIChecks} className="run-api-btn">
          ⚡ Run API/AI Checks
        </button>
      )}
      
      <div className="checks-list">
        {checks.map(check => (
          <div key={check.check} className={`check-item status-${check.status.toLowerCase()}`}>
            <span className="check-icon">{getCheckIcon(check.status)}</span>
            <div className="check-info">
              <h4>{check.check.replace(/_/g, ' ').toUpperCase()}</h4>
              <span className="check-type">{getCheckType(check.check)}</span>
              <span className="check-status">{check.status}</span>
              {check.remarks && (
                <p className="check-remarks">{check.remarks}</p>
              )}
              {check.submittedAt && (
                <span className="check-time">
                  Completed: {new Date(check.submittedAt).toLocaleString()}
                </span>
              )}
            </div>
            {check.status === 'PENDING' && getCheckType(check.check) === 'Manual' && (
              <button 
                onClick={() => setSelectedCheck(check)}
                className="update-btn"
              >
                Mark as Complete
              </button>
            )}
          </div>
        ))}
      </div>
      
      {selectedCheck && (
        <UpdateCheckModal
          check={selectedCheck}
          verificationId={verificationId}
          stage={verification.currentStage}
          onClose={() => setSelectedCheck(null)}
          onSuccess={loadVerification}
        />
      )}
    </div>
  );
}
```

---

### Component 3: Update Check Modal

**Purpose:** Form to mark manual check as complete

```jsx
function UpdateCheckModal({ check, verificationId, stage, onClose, onSuccess }) {
  const [status, setStatus] = useState('COMPLETED');
  const [remarks, setRemarks] = useState('');
  const [errors, setErrors] = useState({});
  
  const checkInstructions = {
    address_verification: 'Visit the candidate\'s address and verify with utility bill, landlord signature, or property documents.',
    education_check_manual: 'Contact the educational institution to verify degree, year, and roll number.',
    supervisory_check: 'Call the candidate\'s previous organization and speak with their supervisor.',
    employment_history_manual: 'Verify employment history through previous employers, documents, or references.'
  };
  
  const validate = () => {
    const newErrors = {};
    
    if (!status) {
      newErrors.status = 'Status is required';
    }
    
    if (!remarks || remarks.length < 20) {
      newErrors.remarks = 'Remarks must be at least 20 characters';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validate()) return;
    
    try {
      const response = await fetch('/secure/updateInternalVerification', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          verificationId,
          stage,
          checkName: check.check,
          status,
          remarks
        })
      });
      
      if (response.ok) {
        onSuccess();
        onClose();
      }
    } catch (error) {
      console.error('Error updating check:', error);
    }
  };
  
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <h2>Complete Check: {check.check.replace(/_/g, ' ')}</h2>
        
        <div className="instructions">
          <strong>Instructions:</strong>
          <p>{checkInstructions[check.check]}</p>
        </div>
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Status *</label>
            <div className="radio-group">
              <label>
                <input
                  type="radio"
                  value="COMPLETED"
                  checked={status === 'COMPLETED'}
                  onChange={(e) => setStatus(e.target.value)}
                />
                ✅ Completed
              </label>
              <label>
                <input
                  type="radio"
                  value="FAILED"
                  checked={status === 'FAILED'}
                  onChange={(e) => setStatus(e.target.value)}
                />
                ❌ Failed
              </label>
              <label>
                <input
                  type="radio"
                  value="IN_PROGRESS"
                  checked={status === 'IN_PROGRESS'}
                  onChange={(e) => setStatus(e.target.value)}
                />
                ⏳ In Progress
              </label>
            </div>
            {errors.status && <span className="error">{errors.status}</span>}
          </div>
          
          <div className="form-group">
            <label>Remarks * (minimum 20 characters)</label>
            <textarea
              value={remarks}
              onChange={(e) => setRemarks(e.target.value)}
              placeholder="Enter detailed remarks about this verification..."
              rows={6}
            />
            <span className="char-count">{remarks.length} characters</span>
            {errors.remarks && <span className="error">{errors.remarks}</span>}
          </div>
          
          <div className="form-actions">
            <button type="button" onClick={onClose}>Cancel</button>
            <button type="submit">Submit</button>
          </div>
        </form>
      </div>
    </div>
  );
}
```

---

## 📝 Complete Implementation Steps

### Step 1: Create Candidate
```javascript
const createCandidate = async (candidateData) => {
  const response = await fetch('/secure/addCandidate', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(candidateData)
  });
  
  const data = await response.json();
  return data.candidateId;
};
```

### Step 2: Initiate Verification with Selected Checks
```javascript
const initiateVerification = async (candidateId, selectedChecks) => {
  const response = await fetch('/secure/initiateStageVerification', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      candidateId,
      organizationId: userOrgId,
      stages: {
        primary: selectedChecks
      }
    })
  });
  
  const data = await response.json();
  return data.verificationId;
};
```

### Step 3: Run API/AI Checks
```javascript
const runAPIChecks = async (verificationId) => {
  const response = await fetch('/secure/runStage', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      verificationId,
      stage: 'primary'
    })
  });
  
  return response.json();
};
```

### Step 4: Poll for Status Updates
```javascript
const pollVerificationStatus = (verificationId, callback) => {
  const interval = setInterval(async () => {
    const response = await fetch(
      `/secure/getVerificationById/${verificationId}`,
      { headers: { 'Authorization': `Bearer ${token}` } }
    );
    
    const data = await response.json();
    callback(data);
    
    // Stop polling if completed
    if (data.overallStatus === 'COMPLETED') {
      clearInterval(interval);
    }
  }, 10000); // Poll every 10 seconds
  
  return interval;
};
```

### Step 5: Update Manual Check
```javascript
const updateManualCheck = async (verificationId, checkName, status, remarks) => {
  const response = await fetch('/secure/updateInternalVerification', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      verificationId,
      stage: 'primary',
      checkName,
      status,
      remarks
    })
  });
  
  return response.json();
};
```

---

## 🎯 Complete User Flow

```
1. User selects candidate
   ↓
2. User selects checks (API + Manual + AI)
   ├─ PAN Verification (API)
   ├─ Address Verification (Manual)
   └─ Resume Validation (AI)
   ↓
3. User clicks "Start Verification"
   → POST /initiateStageVerification
   ↓
4. User clicks "Run API/AI Checks"
   → POST /runStage
   → API checks run automatically (2-3s)
   → AI checks run automatically (5-10s)
   → Manual checks remain PENDING
   ↓
5. UI shows progress: 66% (2/3 complete)
   ✅ PAN: COMPLETED
   ✅ Resume: COMPLETED
   ⏳ Address: PENDING
   ↓
6. Field agent visits address (1-2 days)
   ↓
7. Agent clicks "Mark as Complete"
   → Modal opens
   → Agent fills remarks
   → POST /updateInternalVerification
   ↓
8. UI shows progress: 100% (3/3 complete)
   ✅ All checks COMPLETED
```

---

## 📊 Check Type Reference

### When to Use Each Check:

**API Checks (Use for instant verification):**
- PAN Verification → Verify PAN card
- Aadhaar Verification → Verify Aadhaar card
- Employment History → Verify UAN/EPFO records
- Credit Report → Check credit score
- Court Record → Check criminal records

**Manual Checks (Use when physical verification needed):**
- Address Verification → Site visit required
- Education Check Manual → Call university
- Supervisory Check → Call previous employer
- Employment History Manual → Verify documents

**AI Checks (Use for document analysis):**
- Resume Validation → Check resume authenticity
- Education Manual Check → Manual certificate verification

---

## 🎨 CSS Styling

```css
/* Check Selection Form */
.check-selection-form {
  padding: 20px;
  background: white;
  border-radius: 8px;
}

.check-category {
  margin-bottom: 24px;
}

.check-category h3 {
  margin-bottom: 12px;
  color: #333;
}

.check-item {
  display: flex;
  align-items: center;
  padding: 12px;
  border: 1px solid #e0e0e0;
  border-radius: 4px;
  margin-bottom: 8px;
  cursor: pointer;
}

.check-item:hover {
  background: #f5f5f5;
}

.check-name {
  flex: 1;
  margin-left: 12px;
}

.check-cost {
  color: #2196F3;
  font-weight: bold;
  margin-right: 12px;
}

.check-time {
  color: #666;
  font-size: 14px;
}

/* Verification Detail */
.verification-detail {
  padding: 20px;
}

.progress-bar {
  width: 100%;
  height: 8px;
  background: #e0e0e0;
  border-radius: 4px;
  overflow: hidden;
  margin: 12px 0;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #4CAF50, #8BC34A);
  transition: width 0.3s ease;
}

.checks-list {
  margin-top: 24px;
}

.check-item {
  display: flex;
  align-items: flex-start;
  padding: 16px;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  margin-bottom: 12px;
}

.check-item.status-completed {
  border-left: 4px solid #4CAF50;
}

.check-item.status-failed {
  border-left: 4px solid #f44336;
}

.check-item.status-pending {
  border-left: 4px solid #FFC107;
}

.check-icon {
  font-size: 24px;
  margin-right: 12px;
}

.check-info {
  flex: 1;
}

.check-type {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
  margin-left: 8px;
}

.check-type:contains("API") {
  background: #E3F2FD;
  color: #1976D2;
}

.check-type:contains("Manual") {
  background: #FFF3E0;
  color: #F57C00;
}

.check-type:contains("AI") {
  background: #F3E5F5;
  color: #7B1FA2;
}

/* Modal */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: white;
  padding: 24px;
  border-radius: 8px;
  max-width: 600px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.instructions {
  background: #E3F2FD;
  padding: 12px;
  border-radius: 4px;
  margin-bottom: 20px;
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-weight: 500;
}

.form-group textarea {
  width: 100%;
  padding: 12px;
  border: 1px solid #e0e0e0;
  border-radius: 4px;
  font-family: inherit;
  resize: vertical;
}

.radio-group {
  display: flex;
  gap: 16px;
}

.radio-group label {
  display: flex;
  align-items: center;
  cursor: pointer;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 24px;
}

button {
  padding: 10px 20px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
}

button[type="submit"] {
  background: #2196F3;
  color: white;
}

button[type="button"] {
  background: #e0e0e0;
  color: #333;
}

.error {
  color: #f44336;
  font-size: 12px;
  display: block;
  margin-top: 4px;
}
```

---

That's your complete UI implementation guide with all verification types! 🚀
