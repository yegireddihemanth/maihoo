# Support Staff Ticket Workflow Guide

## **Overview**

Support staff can now see and manage tickets based on:
1. ✅ **Category** (IT staff only see IT tickets)
2. ✅ **Assignment** (see tickets assigned to them)
3. ✅ **Organization** (see tickets from accessible orgs)

---

## **Role-Based Ticket Visibility**

### **1. IT_SUPPORT Role**

**Sees:**
- ✅ Tickets with `category: "IT_ISSUE"`
- ✅ From organizations in `accessibleOrganizations`
- ✅ OR tickets assigned to them (regardless of org)

**Example:**
```javascript
// User: it-support@bgvapp.in
// Role: IT_SUPPORT
// accessibleOrganizations: ["org_acme", "org_techcorp"]

// Sees these tickets:
{
  "ticketId": "TKT-001",
  "category": "IT_ISSUE",  // ✅ IT category
  "organizationId": "org_acme"  // ✅ In accessible orgs
}

{
  "ticketId": "TKT-002",
  "category": "IT_ISSUE",  // ✅ IT category
  "organizationId": "org_xyz",  // ❌ Not in accessible orgs
  "assignedToEmail": "it-support@bgvapp.in"  // ✅ But assigned to them
}

// Does NOT see:
{
  "ticketId": "TKT-003",
  "category": "HR_QUERY",  // ❌ Not IT category
  "organizationId": "org_acme"
}
```

---

### **2. VERIFICATION_SUPPORT Role**

**Sees:**
- ✅ Tickets with `category: "VERIFICATION_ISSUE"`
- ✅ From organizations in `accessibleOrganizations`
- ✅ OR tickets assigned to them

**Example:**
```javascript
// User: verification@bgvapp.in
// Role: VERIFICATION_SUPPORT
// accessibleOrganizations: ["org_acme", "org_techcorp"]

// Sees:
{
  "ticketId": "TKT-004",
  "category": "VERIFICATION_ISSUE",  // ✅ Verification category
  "organizationId": "org_acme"
}

// Does NOT see:
{
  "ticketId": "TKT-005",
  "category": "IT_ISSUE",  // ❌ Not verification
  "organizationId": "org_acme"
}
```

---

### **3. GENERAL_SUPPORT Role**

**Sees:**
- ✅ All ticket categories
- ✅ From organizations in `accessibleOrganizations`
- ✅ OR tickets assigned to them

**Example:**
```javascript
// User: support@bgvapp.in
// Role: GENERAL_SUPPORT
// accessibleOrganizations: ["org_acme"]

// Sees ALL categories from Acme:
{
  "ticketId": "TKT-006",
  "category": "IT_ISSUE",
  "organizationId": "org_acme"
}

{
  "ticketId": "TKT-007",
  "category": "HR_QUERY",
  "organizationId": "org_acme"
}

{
  "ticketId": "TKT-008",
  "category": "BILLING",
  "organizationId": "org_acme"
}
```

---

### **4. SUPER_ADMIN_HELPER Role**

**Sees:**
- ✅ All ticket categories
- ✅ From organizations in `accessibleOrganizations`

**Same as GENERAL_SUPPORT but with more system permissions**

---

## **API Usage Examples**

### **1. View All My Tickets**

```http
GET /secure/ticket/list
Authorization: Bearer <token>
```

**Response for IT_SUPPORT:**
```json
{
  "total": 5,
  "tickets": [
    {
      "ticketId": "TKT-001",
      "subject": "Cannot login",
      "category": "IT_ISSUE",
      "priority": "HIGH",
      "status": "OPEN",
      "organizationName": "Acme Corp",
      "assignedToEmail": "it-support@bgvapp.in"
    },
    {
      "ticketId": "TKT-002",
      "subject": "Server down",
      "category": "IT_ISSUE",
      "priority": "CRITICAL",
      "status": "IN_PROGRESS",
      "organizationName": "TechCorp"
    }
    // Only IT_ISSUE tickets
  ],
  "filters": {
    "role": "IT_SUPPORT",
    "assignedToMe": false,
    "category": null
  }
}
```

---

### **2. View Only Tickets Assigned to Me**

```http
GET /secure/ticket/list?assignedToMe=true
Authorization: Bearer <token>
```

**Response:**
```json
{
  "total": 2,
  "tickets": [
    {
      "ticketId": "TKT-001",
      "assignedToEmail": "it-support@bgvapp.in",
      "status": "OPEN"
    },
    {
      "ticketId": "TKT-003",
      "assignedToEmail": "it-support@bgvapp.in",
      "status": "IN_PROGRESS"
    }
  ]
}
```

---

### **3. Filter by Status**

```http
GET /secure/ticket/list?status=OPEN
Authorization: Bearer <token>
```

**Shows only OPEN tickets in their category/org scope**

---

### **4. Filter by Priority**

```http
GET /secure/ticket/list?priority=CRITICAL
Authorization: Bearer <token>
```

**Shows only CRITICAL tickets in their scope**

---

### **5. Combined Filters**

```http
GET /secure/ticket/list?assignedToMe=true&status=OPEN&priority=HIGH
Authorization: Bearer <token>
```

**Shows only:**
- Assigned to me
- Status = OPEN
- Priority = HIGH
- In my category/org scope

---

## **Complete Workflow Example**

### **Scenario: IT Support Staff Daily Workflow**

#### **Step 1: Login**

```http
POST /auth/login
Content-Type: application/json

{
  "email": "it-support@bgvapp.in",
  "password": "Welcome1"
}
```

**Response:**
```json
{
  "userName": "IT Support Team",
  "email": "it-support@bgvapp.in",
  "role": "IT_SUPPORT",
  "token": "eyJhbGc...",
  "permissions": ["ticket:view", "ticket:update", "ticket:comment"]
}
```

---

#### **Step 2: View All Open IT Tickets**

```http
GET /secure/ticket/list?status=OPEN
Authorization: Bearer eyJhbGc...
```

**Response:**
```json
{
  "total": 3,
  "tickets": [
    {
      "ticketId": "TKT-20241129-1234",
      "subject": "Cannot login to system",
      "description": "Getting 401 error when trying to login",
      "category": "IT_ISSUE",
      "priority": "HIGH",
      "status": "OPEN",
      "organizationName": "Acme Corp",
      "createdBy": "user@acme.com",
      "createdByName": "John Doe",
      "assignedToEmail": "it-support@bgvapp.in",
      "createdAt": "2024-11-29T10:00:00Z",
      "slaDeadline": "2024-11-29T13:00:00Z"
    },
    {
      "ticketId": "TKT-20241129-5678",
      "subject": "Email not working",
      "category": "IT_ISSUE",
      "priority": "MEDIUM",
      "status": "OPEN",
      "organizationName": "TechCorp",
      "assignedToEmail": "it-support@bgvapp.in"
    },
    {
      "ticketId": "TKT-20241129-9012",
      "subject": "VPN connection failed",
      "category": "IT_ISSUE",
      "priority": "HIGH",
      "status": "OPEN",
      "organizationName": "Acme Corp"
    }
  ]
}
```

---

#### **Step 3: Start Working on Ticket**

```http
PUT /secure/ticket/TKT-20241129-1234/status
Authorization: Bearer eyJhbGc...
Content-Type: application/json

{
  "status": "IN_PROGRESS",
  "comment": "Investigating the login issue. Checking authentication logs."
}
```

**Response:**
```json
{
  "message": "Ticket status updated successfully"
}
```

**Email sent to ticket creator:**
```
Hi John Doe,

Your ticket has been updated:

Ticket ID: TKT-20241129-1234
Subject: Cannot login to system
New Status: IN_PROGRESS
Updated By: IT Support Team

Comment: Investigating the login issue. Checking authentication logs.

Thanks,
BGVApp Support Team
```

---

#### **Step 4: Add Progress Comment**

```http
POST /secure/ticket/TKT-20241129-1234/comment
Authorization: Bearer eyJhbGc...
Content-Type: application/json

{
  "comment": "Found the issue - user's account was locked due to multiple failed login attempts. Unlocking now."
}
```

---

#### **Step 5: Resolve Ticket**

```http
PUT /secure/ticket/TKT-20241129-1234/status
Authorization: Bearer eyJhbGc...
Content-Type: application/json

{
  "status": "RESOLVED",
  "comment": "Issue resolved",
  "resolution": "User's account was locked due to 5 failed login attempts. Unlocked the account and verified user can now login successfully. Advised user to use password manager to avoid future lockouts."
}
```

**Response:**
```json
{
  "message": "Ticket status updated successfully"
}
```

**Email sent to creator:**
```
Hi John Doe,

Your ticket has been resolved:

Ticket ID: TKT-20241129-1234
Subject: Cannot login to system
Status: RESOLVED

Resolution: User's account was locked due to 5 failed login attempts. 
Unlocked the account and verified user can now login successfully. 
Advised user to use password manager to avoid future lockouts.

If the issue persists, please reopen this ticket or create a new one.

Thanks,
BGVApp Support Team
```

---

#### **Step 6: View Tickets Assigned to Me**

```http
GET /secure/ticket/list?assignedToMe=true&status=IN_PROGRESS
Authorization: Bearer eyJhbGc...
```

**Shows only tickets:**
- Assigned to `it-support@bgvapp.in`
- Status = IN_PROGRESS
- Category = IT_ISSUE (automatic for IT_SUPPORT role)

---

## **Frontend Implementation**

### **Support Dashboard Component**

```javascript
import React, { useState, useEffect } from 'react';

const SupportDashboard = () => {
  const [tickets, setTickets] = useState([]);
  const [filters, setFilters] = useState({
    assignedToMe: false,
    status: '',
    priority: ''
  });
  
  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');
  
  // Fetch tickets
  useEffect(() => {
    fetchTickets();
  }, [filters]);
  
  const fetchTickets = async () => {
    const params = new URLSearchParams();
    if (filters.assignedToMe) params.append('assignedToMe', 'true');
    if (filters.status) params.append('status', filters.status);
    if (filters.priority) params.append('priority', filters.priority);
    
    const response = await fetch(`/secure/ticket/list?${params}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    const data = await response.json();
    setTickets(data.tickets);
  };
  
  const updateTicketStatus = async (ticketId, status, comment, resolution) => {
    await fetch(`/secure/ticket/${ticketId}/status`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ status, comment, resolution })
    });
    
    fetchTickets(); // Refresh list
  };
  
  return (
    <div className="support-dashboard">
      <h1>Support Tickets</h1>
      
      {/* Filters */}
      <div className="filters">
        <label>
          <input
            type="checkbox"
            checked={filters.assignedToMe}
            onChange={(e) => setFilters({...filters, assignedToMe: e.target.checked})}
          />
          Assigned to Me
        </label>
        
        <select 
          value={filters.status}
          onChange={(e) => setFilters({...filters, status: e.target.value})}
        >
          <option value="">All Status</option>
          <option value="OPEN">Open</option>
          <option value="IN_PROGRESS">In Progress</option>
          <option value="RESOLVED">Resolved</option>
          <option value="CLOSED">Closed</option>
        </select>
        
        <select
          value={filters.priority}
          onChange={(e) => setFilters({...filters, priority: e.target.value})}
        >
          <option value="">All Priority</option>
          <option value="LOW">Low</option>
          <option value="MEDIUM">Medium</option>
          <option value="HIGH">High</option>
          <option value="CRITICAL">Critical</option>
        </select>
      </div>
      
      {/* Tickets Table */}
      <table>
        <thead>
          <tr>
            <th>Ticket ID</th>
            <th>Subject</th>
            <th>Category</th>
            <th>Priority</th>
            <th>Status</th>
            <th>Organization</th>
            <th>Created</th>
            <th>SLA Deadline</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {tickets.map(ticket => (
            <tr key={ticket.ticketId} className={getSLAClass(ticket)}>
              <td>{ticket.ticketId}</td>
              <td>{ticket.subject}</td>
              <td>
                <span className={`badge ${ticket.category}`}>
                  {ticket.category}
                </span>
              </td>
              <td>
                <span className={`priority ${ticket.priority}`}>
                  {ticket.priority}
                </span>
              </td>
              <td>
                <span className={`status ${ticket.status}`}>
                  {ticket.status}
                </span>
              </td>
              <td>{ticket.organizationName}</td>
              <td>{formatDate(ticket.createdAt)}</td>
              <td>{formatDate(ticket.slaDeadline)}</td>
              <td>
                <button onClick={() => viewTicket(ticket.ticketId)}>
                  View
                </button>
                {ticket.status === 'OPEN' && (
                  <button onClick={() => startWorking(ticket.ticketId)}>
                    Start
                  </button>
                )}
                {ticket.status === 'IN_PROGRESS' && (
                  <button onClick={() => resolveTicket(ticket.ticketId)}>
                    Resolve
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

// Helper functions
const getSLAClass = (ticket) => {
  const now = new Date();
  const deadline = new Date(ticket.slaDeadline);
  const hoursLeft = (deadline - now) / (1000 * 60 * 60);
  
  if (ticket.status === 'RESOLVED' || ticket.status === 'CLOSED') {
    return 'completed';
  }
  if (hoursLeft < 0) return 'sla-breached';
  if (hoursLeft < 2) return 'sla-warning';
  return 'sla-ok';
};

const formatDate = (dateStr) => {
  return new Date(dateStr).toLocaleString();
};

export default SupportDashboard;
```

---

## **Access Control Summary**

| Role | Sees Tickets | Can Update | Can Comment | Scope |
|------|-------------|------------|-------------|-------|
| **IT_SUPPORT** | IT_ISSUE only | ✅ IT tickets | ✅ IT tickets | Accessible orgs + assigned |
| **VERIFICATION_SUPPORT** | VERIFICATION_ISSUE only | ✅ Verification tickets | ✅ Verification tickets | Accessible orgs + assigned |
| **GENERAL_SUPPORT** | All categories | ✅ All tickets | ✅ All tickets | Accessible orgs + assigned |
| **SUPER_ADMIN_HELPER** | All categories | ✅ All tickets | ✅ All tickets | Accessible orgs |
| **SPOC/ORG_HR** | All categories | ✅ Own org tickets | ✅ Own org tickets | Own org only |
| **HELPER** | All categories | ❌ | ✅ Own tickets | Created by them |

---

## **Key Features**

### **1. Category-Based Filtering**
- ✅ IT staff only see IT tickets
- ✅ Verification staff only see verification tickets
- ✅ General support sees all categories

### **2. Assignment-Based Filtering**
- ✅ `?assignedToMe=true` shows only tickets assigned to logged-in user
- ✅ Support staff see tickets assigned to them even from non-accessible orgs

### **3. Organization-Based Filtering**
- ✅ Support staff see tickets from `accessibleOrganizations`
- ✅ Can handle multiple organizations

### **4. Combined Filtering**
- ✅ Can combine: category + assignment + status + priority
- ✅ Example: "Show me HIGH priority OPEN IT tickets assigned to me"

---

## **Testing Checklist**

### **Test IT Support Access**

```bash
# 1. Create IT Support user
POST /secure/addHelper
{
  "email": "it-support@bgvapp.in",
  "role": "IT_SUPPORT",
  "accessibleOrganizations": ["org1", "org2"]
}

# 2. Login as IT Support
POST /auth/login
{ "email": "it-support@bgvapp.in", "password": "Welcome1" }

# 3. View tickets (should only see IT_ISSUE)
GET /secure/ticket/list

# 4. Try to view HR ticket (should not appear)
# Create HR ticket from org1, IT support should NOT see it

# 5. View assigned tickets
GET /secure/ticket/list?assignedToMe=true

# 6. Update IT ticket status
PUT /secure/ticket/TKT-xxx/status
{ "status": "IN_PROGRESS", "comment": "Working on it" }

# 7. Try to update HR ticket (should fail with 403)
```

---

## **Summary**

✅ **Support staff now see only relevant tickets:**
- IT Support → IT tickets only
- Verification Support → Verification tickets only
- General Support → All tickets

✅ **Can filter by:**
- Assigned to me
- Status
- Priority
- Category (automatic based on role)

✅ **Can manage tickets:**
- Update status
- Add comments
- Resolve with resolution text

✅ **Proper authorization:**
- Can only update tickets in their category/org scope
- Cannot access tickets outside their domain

