# Frontend Quick Reference - Manual Verification

## 🚀 Quick Start for Frontend Developers

### 3 Simple Steps:

1. **Show list of verifications** → Call GET API
2. **Show verification details** → Call GET API  
3. **Update a check** → Call POST API

---

## 📋 API Endpoints You Need

### 1. Get List of Verifications
```javascript
GET /secure/getVerificationsByOrganization?organizationId={orgId}

// Response:
{
  "verifications": [
    {
      "_id": "ver_123",
      "candidateName": "John Doe",
      "completionPercentage": 50,
      "totalChecks": 4,
      "completedChecks": 2,
      "stages": { ... }
    }
  ]
}
```

### 2. Get Verification Details
```javascript
GET /secure/getVerificationById/{verificationId}

// Response:
{
  "_id": "ver_123",
  "candidateName": "John Doe",
  "stages": {
    "primary": [
      {"check": "pan_verification", "status": "COMPLETED"},
      {"check": "address_verification", "status": "PENDING"}
    ]
  }
}
```

### 3. Update a Check
```javascript
POST /secure/updateInternalVerification
Content-Type: application/json

{
  "verificationId": "ver_123",
  "stage": "primary",
  "checkName": "address_verification",
  "status": "COMPLETED",
  "remarks": "Visited site, confirmed address"
}

// Response:
{
  "check": "address_verification",
  "status": "COMPLETED",
  "stageCompleted": false
}
```

---

## 💻 Example React Components

### List Page
```jsx
import { useState, useEffect } from 'react';

function VerificationList() {
  const [verifications, setVerifications] = useState([]);
  
  useEffect(() => {
    fetch('/secure/getVerificationsByOrganization?organizationId=org_123')
      .then(res => res.json())
      .then(data => setVerifications(data.verifications));
  }, []);
  
  return (
    <div>
      <h1>Manual Verifications</h1>
      {verifications.map(v => (
        <VerificationCard key={v._id} verification={v} />
      ))}
    </div>
  );
}

function VerificationCard({ verification }) {
  return (
    <div className="card">
      <h3>{verification.candidateName}</h3>
      <p>Progress: {verification.completionPercentage}%</p>
      <p>Checks: {verification.completedChecks}/{verification.totalChecks}</p>
      <button onClick={() => navigate(`/verification/${verification._id}`)}>
        View Details
      </button>
    </div>
  );
}
```

### Detail Page
```jsx
import { useState, useEffect } from 'react';

function VerificationDetail({ verificationId }) {
  const [verification, setVerification] = useState(null);
  const [selectedCheck, setSelectedCheck] = useState(null);
  
  useEffect(() => {
    loadVerification();
  }, [verificationId]);
  
  const loadVerification = () => {
    fetch(`/secure/getVerificationById/${verificationId}`)
      .then(res => res.json())
      .then(data => setVerification(data));
  };
  
  const handleUpdateCheck = async (checkName, status, remarks) => {
    const response = await fetch('/secure/updateInternalVerification', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        verificationId,
        stage: verification.currentStage,
        checkName,
        status,
        remarks
      })
    });
    
    if (response.ok) {
      loadVerification(); // Refresh data
      setSelectedCheck(null); // Close modal
    }
  };
  
  if (!verification) return <div>Loading...</div>;
  
  return (
    <div>
      <h1>{verification.candidateName}</h1>
      <p>Email: {verification.candidateEmail}</p>
      <p>Stage: {verification.currentStage}</p>
      
      <h2>Checks</h2>
      {verification.stages[verification.currentStage]?.map(check => (
        <CheckItem
          key={check.check}
          check={check}
          onUpdate={() => setSelectedCheck(check)}
        />
      ))}
      
      {selectedCheck && (
        <UpdateCheckModal
          check={selectedCheck}
          onSubmit={handleUpdateCheck}
          onClose={() => setSelectedCheck(null)}
        />
      )}
    </div>
  );
}

function CheckItem({ check, onUpdate }) {
  const getStatusIcon = (status) => {
    if (status === 'COMPLETED') return '✅';
    if (status === 'FAILED') return '❌';
    if (status === 'IN_PROGRESS') return '⏳';
    return '⏳';
  };
  
  return (
    <div className="check-item">
      <span>{getStatusIcon(check.status)}</span>
      <span>{check.check}</span>
      <span>{check.status}</span>
      {check.status === 'PENDING' && (
        <button onClick={onUpdate}>Mark as Complete</button>
      )}
      {check.remarks && <p>Remarks: {check.remarks}</p>}
    </div>
  );
}
```

### Update Modal
```jsx
import { useState } from 'react';

function UpdateCheckModal({ check, onSubmit, onClose }) {
  const [status, setStatus] = useState('COMPLETED');
  const [remarks, setRemarks] = useState('');
  const [errors, setErrors] = useState({});
  
  const validate = () => {
    const newErrors = {};
    
    if (!status) {
      newErrors.status = 'Status is required';
    }
    
    if (!remarks || remarks.length < 10) {
      newErrors.remarks = 'Remarks must be at least 10 characters';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };
  
  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (validate()) {
      onSubmit(check.check, status, remarks);
    }
  };
  
  return (
    <div className="modal">
      <div className="modal-content">
        <h2>Update Check: {check.check}</h2>
        
        <form onSubmit={handleSubmit}>
          <div>
            <label>Status:</label>
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="COMPLETED">Completed</option>
              <option value="FAILED">Failed</option>
              <option value="IN_PROGRESS">In Progress</option>
            </select>
            {errors.status && <span className="error">{errors.status}</span>}
          </div>
          
          <div>
            <label>Remarks:</label>
            <textarea
              value={remarks}
              onChange={(e) => setRemarks(e.target.value)}
              placeholder="Enter detailed remarks about this verification..."
              rows={5}
            />
            {errors.remarks && <span className="error">{errors.remarks}</span>}
          </div>
          
          <div className="buttons">
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

## 🎨 CSS Styling Examples

```css
/* Verification Card */
.card {
  border: 1px solid #ddd;
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 16px;
  background: white;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

/* Check Item */
.check-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  border-bottom: 1px solid #eee;
}

.check-item:last-child {
  border-bottom: none;
}

/* Status Badge */
.status-completed { color: #22c55e; }
.status-failed { color: #ef4444; }
.status-pending { color: #f59e0b; }
.status-in-progress { color: #3b82f6; }

/* Progress Bar */
.progress-bar {
  width: 100%;
  height: 8px;
  background: #e5e7eb;
  border-radius: 4px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: #3b82f6;
  transition: width 0.3s ease;
}

/* Modal */
.modal {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0,0,0,0.5);
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-content {
  background: white;
  padding: 24px;
  border-radius: 8px;
  max-width: 500px;
  width: 90%;
}
```

---

## 🔄 State Management (Redux Example)

```javascript
// verificationSlice.js
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';

export const fetchVerifications = createAsyncThunk(
  'verification/fetchList',
  async (organizationId) => {
    const response = await fetch(
      `/secure/getVerificationsByOrganization?organizationId=${organizationId}`
    );
    return response.json();
  }
);

export const fetchVerificationDetail = createAsyncThunk(
  'verification/fetchDetail',
  async (verificationId) => {
    const response = await fetch(`/secure/getVerificationById/${verificationId}`);
    return response.json();
  }
);

export const updateCheck = createAsyncThunk(
  'verification/updateCheck',
  async ({ verificationId, stage, checkName, status, remarks }) => {
    const response = await fetch('/secure/updateInternalVerification', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verificationId, stage, checkName, status, remarks })
    });
    return response.json();
  }
);

const verificationSlice = createSlice({
  name: 'verification',
  initialState: {
    list: [],
    current: null,
    loading: false,
    error: null
  },
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(fetchVerifications.fulfilled, (state, action) => {
        state.list = action.payload.verifications;
        state.loading = false;
      })
      .addCase(fetchVerificationDetail.fulfilled, (state, action) => {
        state.current = action.payload;
        state.loading = false;
      })
      .addCase(updateCheck.fulfilled, (state, action) => {
        // Refresh current verification
        state.loading = false;
      });
  }
});

export default verificationSlice.reducer;
```

---

## 📱 Mobile-Friendly Example

```jsx
// Mobile-optimized component
function MobileCheckUpdate({ check, onSubmit }) {
  const [status, setStatus] = useState('COMPLETED');
  const [remarks, setRemarks] = useState('');
  const [photo, setPhoto] = useState(null);
  
  const handlePhotoCapture = (e) => {
    const file = e.target.files[0];
    setPhoto(file);
  };
  
  return (
    <div className="mobile-form">
      <h2>{check.check}</h2>
      
      {/* Large touch-friendly buttons */}
      <div className="status-buttons">
        <button
          className={status === 'COMPLETED' ? 'active' : ''}
          onClick={() => setStatus('COMPLETED')}
        >
          ✅ Completed
        </button>
        <button
          className={status === 'FAILED' ? 'active' : ''}
          onClick={() => setStatus('FAILED')}
        >
          ❌ Failed
        </button>
      </div>
      
      {/* Voice input for remarks */}
      <textarea
        value={remarks}
        onChange={(e) => setRemarks(e.target.value)}
        placeholder="Tap to type or use voice input..."
      />
      
      {/* Camera capture */}
      <div className="photo-capture">
        <input
          type="file"
          accept="image/*"
          capture="environment"
          onChange={handlePhotoCapture}
        />
        {photo && <img src={URL.createObjectURL(photo)} alt="Evidence" />}
      </div>
      
      <button
        className="submit-button"
        onClick={() => onSubmit(check.check, status, remarks, photo)}
      >
        Submit
      </button>
    </div>
  );
}
```

---

## ✅ Checklist for Frontend Team

- [ ] Create verification list page
- [ ] Create verification detail page
- [ ] Create update check modal/form
- [ ] Add progress bar component
- [ ] Add status badges (completed, pending, failed)
- [ ] Implement form validation
- [ ] Add loading states
- [ ] Add error handling
- [ ] Test on mobile devices
- [ ] Add refresh/polling for real-time updates
- [ ] Handle permissions (show/hide based on user role)

---

## 🎯 Summary

**3 API calls:**
1. GET list
2. GET details
3. POST update

**3 main components:**
1. List page
2. Detail page
3. Update modal

**Data to send:**
```javascript
{
  verificationId: "ver_123",
  stage: "primary",
  checkName: "address_verification",
  status: "COMPLETED",
  remarks: "Detailed notes here"
}
```

That's it! Simple and straightforward. 🚀
