# Enhanced Ticket Management System

## Overview
The new ticket system provides intelligent routing based on issue type, priority-based SLA tracking, and team-based notifications.

---

## Key Features

### 1. **Smart Category-Based Routing**

| Category | Routes To | SLA | Use Case |
|----------|-----------|-----|----------|
| `IT_ISSUE` | IT Team | 4 hours | Login issues, system errors, technical problems |
| `VERIFICATION_ISSUE` | Verification Team | 24 hours | Background check problems |
| `HR_QUERY` | HR Team | 48 hours | Policy questions, general HR queries |
| `BILLING` | Finance Team | 12 hours | Payment issues, invoice problems |
| `BUG_REPORT` | Dev Team | 8 hours | Software bugs |
| `FEATURE_REQUEST` | Product Team | 1 week | New feature suggestions |
| `ACCOUNT_ISSUE` | Support Team | 12 hours | Account access, permissions |
| `OTHER` | Support Team | 24 hours | General queries |

### 2. **Priority Levels**

- **CRITICAL**: 50% of base SLA (immediate escalation to SUPER_SPOC)
- **HIGH**: 75% of base SLA
- **MEDIUM**: 100% of base SLA (default)
- **LOW**: 150% of base SLA

### 3. **Automatic Notifications**

When a ticket is created:
1. ✅ Email sent to assigned user
2. ✅ Email sent to relevant team (IT team, HR team, etc.)
3. ✅ Activity logged in system
4. ✅ SLA deadline calculated

---

## API Endpoints

### **1. Get Available Categories**
```http
GET /secure/ticket/categories
Authorization: Bearer <token>
```

**Response:**
```json
{
  "categories": [
    {
      "value": "IT_ISSUE",
      "label": "IT Support",
      "description": "Technical issues, login problems, system errors",
      "priority": "HIGH",
      "sla_hours": 4
    },
    ...
  ]
}
```

---

### **2. Create Ticket**
```http
POST /secure/ticket/create
Authorization: Bearer <token>
Content-Type: application/json

{
  "subject": "Cannot login to system",
  "description": "Getting 401 error when trying to login with correct credentials",
  "category": "IT_ISSUE",
  "priority": "HIGH",
  "attachments": ["https://cloudinary.com/screenshot.png"]
}
```

**Response:**
```json
{
  "message": "Ticket created successfully",
  "ticketId": "TKT-20241129120530-1234",
  "assignedTo": "John Doe",
  "slaDeadline": "2024-11-29T16:05:30Z",
  "ticket": { ... }
}
```

---

### **3. List Tickets**
```http
GET /secure/ticket/list?status=OPEN&category=IT_ISSUE&priority=HIGH
Authorization: Bearer <token>
```

**Role-based filtering:**
- **SUPER_ADMIN/SUPER_SPOC**: See all tickets
- **SUPER_ADMIN_HELPER**: Tickets from assigned orgs
- **SPOC/ORG_HR**: Tickets from their org
- **HELPER**: Only tickets they created

---

### **4. Get Single Ticket**
```http
GET /secure/ticket/TKT-20241129120530-1234
Authorization: Bearer <token>
```

---

### **5. Update Ticket Status**
```http
PUT /secure/ticket/TKT-20241129120530-1234/status
Authorization: Bearer <token>
Content-Type: application/json

{
  "status": "RESOLVED",
  "comment": "Fixed by restarting the authentication service",
  "resolution": "The issue was caused by a stuck Redis connection. Restarted the service and verified login works."
}
```

**Valid statuses:**
- `OPEN` - Initial state
- `IN_PROGRESS` - Being worked on
- `RESOLVED` - Fixed (requires resolution text)
- `CLOSED` - Completed and verified
- `REOPENED` - Issue returned

---

### **6. Add Comment**
```http
POST /secure/ticket/TKT-20241129120530-1234/comment
Authorization: Bearer <token>
Content-Type: application/json

{
  "comment": "I've checked the logs and found the root cause. Working on a fix."
}
```

---

### **7. Reassign Ticket (Admin Only)**
```http
PUT /secure/ticket/TKT-20241129120530-1234/reassign
Authorization: Bearer <token>
Content-Type: application/json

{
  "assignedToEmail": "it-specialist@bgvapp.in",
  "reason": "Requires specialized IT knowledge"
}
```

---

## Assignment Logic

### **Hierarchical Assignment (Non-IT Issues)**
```
HELPER → ORG_HR → SPOC → SUPER_ADMIN → SUPER_SPOC
```

### **IT Issues (Special Routing)**
```
Anyone → IT_TEAM (round-robin) → SUPER_ADMIN (if no IT team)
```

### **Critical Priority**
```
Anyone → SUPER_SPOC (immediate escalation)
```

---

## Team Email Configuration

Update these in `utils/ticket_utils.py`:

```python
TEAM_EMAILS = {
    "IT_TEAM": ["it-support@bgvapp.in", "tech@bgvapp.in"],
    "VERIFICATION_TEAM": ["verification@bgvapp.in"],
    "HR_TEAM": ["hr@bgvapp.in"],
    "FINANCE_TEAM": ["finance@bgvapp.in"],
    "PRODUCT_TEAM": ["product@bgvapp.in"],
    "DEV_TEAM": ["dev@bgvapp.in"],
    "SUPPORT_TEAM": ["support@bgvapp.in"]
}
```

---

## Frontend Integration

### **1. Ticket Creation Form**

```javascript
// Fetch categories
const categories = await fetch('/secure/ticket/categories', {
  headers: { 'Authorization': `Bearer ${token}` }
}).then(r => r.json());

// Create ticket
const ticket = await fetch('/secure/ticket/create', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    subject: formData.subject,
    description: formData.description,
    category: formData.category, // "IT_ISSUE"
    priority: formData.priority,  // "HIGH"
    attachments: uploadedFiles
  })
}).then(r => r.json());
```

### **2. IT Issue Toggle**

```javascript
// When user toggles "This is an IT issue" checkbox
const handleITToggle = (isITIssue) => {
  if (isITIssue) {
    setCategory('IT_ISSUE');
    setPriority('HIGH'); // Auto-set to HIGH for IT issues
  }
};
```

### **3. Ticket List with Filters**

```javascript
const tickets = await fetch(
  `/secure/ticket/list?status=OPEN&category=IT_ISSUE&priority=HIGH`,
  { headers: { 'Authorization': `Bearer ${token}` } }
).then(r => r.json());
```

---

## Database Schema

### **Ticket Document**
```javascript
{
  "_id": ObjectId,
  "ticketId": "TKT-20241129120530-1234",
  "subject": "Cannot login",
  "description": "Getting 401 error...",
  "category": "IT_ISSUE",
  "priority": "HIGH",
  "status": "OPEN",
  
  // Creator info
  "createdBy": "user@company.com",
  "createdByName": "John Doe",
  "createdByRole": "ORG_HR",
  "organizationId": "org123",
  "organizationName": "Acme Corp",
  
  // Assignment info
  "assignedTo": "userId",
  "assignedToEmail": "it@bgvapp.in",
  "assignedToName": "IT Support",
  "assignedToRole": "IT_SUPPORT",
  
  // Tracking
  "attachments": [],
  "comments": [
    {
      "comment": "Working on it",
      "commentedBy": "it@bgvapp.in",
      "commentedByName": "IT Support",
      "commentedByRole": "IT_SUPPORT",
      "commentedAt": "2024-11-29T12:30:00Z"
    }
  ],
  "statusHistory": [
    {
      "status": "OPEN",
      "changedBy": "user@company.com",
      "changedAt": "2024-11-29T12:05:30Z",
      "comment": "Ticket created"
    }
  ],
  
  // Timestamps
  "createdAt": "2024-11-29T12:05:30Z",
  "updatedAt": "2024-11-29T12:30:00Z",
  "slaDeadline": "2024-11-29T16:05:30Z",
  "resolvedAt": null,
  "resolution": null
}
```

---

## Benefits Over Old System

| Old System | New System |
|------------|------------|
| ❌ Always assigns to first SUPER_ADMIN | ✅ Smart routing based on issue type |
| ❌ No IT team support | ✅ Dedicated IT team routing |
| ❌ No SLA tracking | ✅ Automatic SLA calculation |
| ❌ No team notifications | ✅ Email to relevant teams |
| ❌ No priority handling | ✅ 4 priority levels with SLA adjustment |
| ❌ Single assignment path | ✅ Multiple routing strategies |
| ❌ No load balancing | ✅ Round-robin for IT team |

---

## Next Steps

1. ✅ **Configure team emails** in `ticket_utils.py`
2. ✅ **Add IT_SUPPORT role** to your user roles (optional)
3. ✅ **Test ticket creation** with different categories
4. ✅ **Update frontend** to use new categories endpoint
5. ✅ **Add SLA monitoring** dashboard (future enhancement)

---

## Example Scenarios

### **Scenario 1: ORG_HR has login issue**
1. ORG_HR creates ticket with category `IT_ISSUE`, priority `HIGH`
2. System routes to IT_TEAM (if exists) or SUPER_ADMIN
3. Email sent to IT team members
4. SLA deadline: 3 hours (4 hours × 0.75 for HIGH priority)
5. IT team member resolves and marks as RESOLVED

### **Scenario 2: HELPER has verification question**
1. HELPER creates ticket with category `VERIFICATION_ISSUE`, priority `MEDIUM`
2. System assigns to ORG_HR (hierarchical)
3. Email sent to verification team
4. SLA deadline: 24 hours
5. ORG_HR can reassign to SUPER_ADMIN_HELPER if needed

### **Scenario 3: Critical system outage**
1. Anyone creates ticket with priority `CRITICAL`
2. System immediately escalates to SUPER_SPOC
3. Email sent to escalation team
4. SLA deadline: 50% of normal (2 hours for IT issues)
5. SUPER_SPOC coordinates resolution

---

## Support

For questions about the ticket system, contact: support@bgvapp.in
