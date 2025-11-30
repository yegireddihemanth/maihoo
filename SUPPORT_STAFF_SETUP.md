# Support Staff User Setup Guide

## **Understanding the Two Layers**

```
┌─────────────────────────────────────────────────────────┐
│                    LAYER 1: EMAIL ONLY                  │
│  (No user account needed - just receives notifications) │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  GLOBAL_TEAM_EMAILS = {                                │
│    "IT_TEAM": ["it-support@bgvapp.in"]                 │
│  }                                                      │
│                                                         │
│  ✅ Receives email when ticket created                 │
│  ❌ Cannot login to system                             │
│  ❌ Cannot view tickets in UI                          │
│  ❌ Cannot update ticket status                        │
│                                                         │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                    LAYER 2: FULL ACCESS                 │
│  (User account required - can login and manage tickets) │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  users collection: {                                   │
│    email: "it-support@bgvapp.in",                      │
│    role: "IT_SUPPORT",                                 │
│    password: "Welcome1"                                │
│  }                                                      │
│                                                         │
│  ✅ Receives email when ticket created                 │
│  ✅ Can login to system                                │
│  ✅ Can view tickets in UI                             │
│  ✅ Can update ticket status                           │
│  ✅ Can add comments                                   │
│  ✅ Can reassign tickets                               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## **Recommended Approach**

### **Option 1: Email-Only (Minimal Setup)**

**Use Case:** Support staff just need to be notified, they respond via email

**Setup:**
```python
# In ticket_utils.py
GLOBAL_TEAM_EMAILS = {
    "IT_TEAM": ["it-support@bgvapp.in"],
    "SUPPORT_TEAM": ["support@bgvapp.in"]
}
```

**No user accounts needed!**

**Workflow:**
1. User creates ticket
2. Email sent to `it-support@bgvapp.in`
3. IT staff reads email
4. IT staff responds via email or external system
5. SUPER_ADMIN manually updates ticket status in UI

**Pros:**
- ✅ Simple setup
- ✅ No user management

**Cons:**
- ❌ Support staff can't see tickets in UI
- ❌ Admin must manually update ticket status

---

### **Option 2: Full Access (Recommended)**

**Use Case:** Support staff need to login, view tickets, update status

**Setup:** Create user accounts for each support staff member

---

## **User Schema for Support Staff**

### **Schema Template**

```javascript
{
  // REQUIRED FIELDS
  "_id": ObjectId("auto-generated"),
  "userName": "IT Support Team",
  "email": "it-support@bgvapp.in",  // MUST match GLOBAL_TEAM_EMAILS
  "password": "Welcome1",            // Default password (user should change)
  "role": "IT_SUPPORT",              // NEW ROLE (or use existing)
  "isActive": true,
  
  // ORGANIZATION ASSIGNMENT
  "organizationId": "bgv_central_org_id",  // BGV's own org ID
  
  // PERMISSIONS (what they can do)
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "ticket:reassign",
    "dashboard:view"
  ],
  
  // FOR MULTI-ORG ACCESS (if using SUPER_ADMIN_HELPER role)
  "accessibleOrganizations": [
    "org_acme_id",
    "org_techcorp_id",
    "org_xyz_id"
  ],
  
  // METADATA
  "phoneNumber": "+1234567890",
  "createdAt": "2024-11-29T12:00:00Z",
  "createdBy": "admin@bgvapp.in"
}
```

---

## **Role Options for Support Staff**

### **Option A: Create New Roles (Recommended)**

Add these new roles to your system:

#### **1. IT_SUPPORT Role**

```javascript
{
  "userName": "IT Support",
  "email": "it-support@bgvapp.in",
  "role": "IT_SUPPORT",
  "organizationId": "bgv_central",
  "permissions": [
    "ticket:view",           // View all IT tickets
    "ticket:update",         // Update ticket status
    "ticket:comment",        // Add comments
    "ticket:reassign",       // Reassign to others
    "dashboard:view"         // View dashboard
  ],
  "accessibleOrganizations": ["org1", "org2", "org3"]  // Can access these orgs
}
```

**Access Pattern:**
- Sees tickets with `category: "IT_ISSUE"` from accessible orgs
- Can update any IT ticket
- Cannot access verification or HR tickets

---

#### **2. VERIFICATION_SUPPORT Role**

```javascript
{
  "userName": "Verification Specialist",
  "email": "verification@bgvapp.in",
  "role": "VERIFICATION_SUPPORT",
  "organizationId": "bgv_central",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "verification:view",     // Can view verifications
    "verification:assign",   // Can assign verifications
    "candidate:view"         // Can view candidates
  ],
  "accessibleOrganizations": ["org1", "org2", "org3"]
}
```

**Access Pattern:**
- Sees tickets with `category: "VERIFICATION_ISSUE"`
- Can also access verification records
- Can help with background check issues

---

#### **3. GENERAL_SUPPORT Role**

```javascript
{
  "userName": "General Support",
  "email": "support@bgvapp.in",
  "role": "GENERAL_SUPPORT",
  "organizationId": "bgv_central",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment"
  ],
  "accessibleOrganizations": ["org1", "org2", "org3"]
}
```

**Access Pattern:**
- Sees all ticket categories from accessible orgs
- General support for any issue type

---

### **Option B: Use Existing Roles**

If you don't want to add new roles, use existing ones:

#### **Use SUPER_ADMIN_HELPER**

```javascript
{
  "userName": "IT Support",
  "email": "it-support@bgvapp.in",
  "role": "SUPER_ADMIN_HELPER",  // Existing role
  "organizationId": "bgv_central",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "organization:view",
    "verification:view"
  ],
  "accessibleOrganizations": ["org1", "org2", "org3"]
}
```

**Access Pattern:**
- Sees all tickets from accessible orgs
- Can also view organizations and verifications
- More permissions than needed (but works)

---

## **How to Create Support Staff Users**

### **Method 1: Via API (Recommended)**

```http
POST /secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "userName": "IT Support Team",
  "email": "it-support@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+1234567890",
  "organizationId": "bgv_central_org_id",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "ticket:reassign",
    "dashboard:view"
  ],
  "accessibleOrganizations": [
    "org_acme_id",
    "org_techcorp_id"
  ]
}
```

**Response:**
```json
{
  "message": "Helper user added successfully",
  "helper": {
    "userId": "user123",
    "email": "it-support@bgvapp.in",
    "role": "SUPER_ADMIN_HELPER",
    "defaultPassword": "Welcome1"
  }
}
```

---

### **Method 2: Direct MongoDB Insert**

```javascript
// MongoDB shell or Compass
db.users.insertOne({
  "userName": "IT Support Team",
  "email": "it-support@bgvapp.in",
  "password": "Welcome1",  // In production, hash this!
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+1234567890",
  "organizationId": ObjectId("bgv_central_org_id"),
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "ticket:reassign",
    "dashboard:view"
  ],
  "accessibleOrganizations": [
    "org_acme_id",
    "org_techcorp_id"
  ],
  "isActive": true,
  "createdAt": new Date().toISOString(),
  "createdBy": "admin@bgvapp.in"
})
```

---

## **How They Access Tickets**

### **Step 1: Login**

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
  "role": "SUPER_ADMIN_HELPER",
  "token": "eyJhbGc...",
  "permissions": ["ticket:view", "ticket:update", ...]
}
```

---

### **Step 2: View Tickets**

```http
GET /secure/ticket/list
Authorization: Bearer eyJhbGc...
```

**Backend automatically filters based on role:**

```python
# In main.py getTickets endpoint
if role == "SUPER_ADMIN_HELPER":
    accessible = user.get("accessibleOrganizations", [])
    query["organizationId"] = {"$in": accessible}
```

**Response:**
```json
{
  "total": 15,
  "tickets": [
    {
      "ticketId": "TKT-20241129-1234",
      "subject": "Cannot login",
      "category": "IT_ISSUE",
      "priority": "HIGH",
      "status": "OPEN",
      "organizationName": "Acme Corp",
      "createdBy": "user@acme.com",
      "assignedToEmail": "it-support@bgvapp.in"
    },
    // ... more tickets from accessible orgs
  ]
}
```

---

### **Step 3: Update Ticket**

```http
PUT /secure/ticket/TKT-20241129-1234/status
Authorization: Bearer eyJhbGc...
Content-Type: application/json

{
  "status": "IN_PROGRESS",
  "comment": "Investigating the login issue"
}
```

---

### **Step 4: Resolve Ticket**

```http
PUT /secure/ticket/TKT-20241129-1234/status
Authorization: Bearer eyJhbGc...
Content-Type: application/json

{
  "status": "RESOLVED",
  "comment": "Fixed by resetting password",
  "resolution": "User's password was expired. Reset password and verified login works."
}
```

---

## **Access Control Matrix**

| Role | Can View Tickets | Can Update | Can Reassign | Scope |
|------|-----------------|------------|--------------|-------|
| **SUPER_ADMIN** | All tickets | ✅ | ✅ | All orgs |
| **SUPER_SPOC** | All tickets | ✅ | ✅ | All orgs |
| **SUPER_ADMIN_HELPER** | Assigned orgs | ✅ | ✅ | accessibleOrganizations |
| **IT_SUPPORT** (new) | IT tickets | ✅ | ✅ | accessibleOrganizations |
| **SPOC** | Own org | ✅ | ✅ | Own org only |
| **ORG_HR** | Own org | ✅ | ❌ | Own org only |
| **HELPER** | Own tickets | ❌ | ❌ | Created by them |

---

## **Complete Setup Example**

### **Scenario: Setup IT Support for 3 Organizations**

#### **Step 1: Configure Email Notifications**

```python
# In ticket_utils.py
GLOBAL_TEAM_EMAILS = {
    "IT_TEAM": ["it-support@bgvapp.in", "tech-lead@bgvapp.in"]
}
```

#### **Step 2: Create BGV Central Organization (if not exists)**

```http
POST /secure/registerOrganization
{
  "organizationName": "BGV Central",
  "spocName": "Admin",
  "email": "admin@bgvapp.in",
  "subDomain": "bgv.local",
  "gstNumber": "BGV123",
  "services": [],
  "credentials": { "totalAllowed": 50, "used": 0 }
}
```

**Response:** `organizationId: "bgv_central_id"`

#### **Step 3: Create IT Support User**

```http
POST /secure/addHelper
{
  "userName": "IT Support Team",
  "email": "it-support@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "organizationId": "bgv_central_id",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "ticket:reassign"
  ],
  "accessibleOrganizations": [
    "org_acme_id",
    "org_techcorp_id",
    "org_xyz_id"
  ]
}
```

#### **Step 4: Test Login**

```http
POST /auth/login
{
  "email": "it-support@bgvapp.in",
  "password": "Welcome1"
}
```

#### **Step 5: Test Ticket Access**

```http
GET /secure/ticket/list
Authorization: Bearer <token>
```

**Should see tickets from Acme, TechCorp, and XYZ only.**

---

## **Frontend Integration**

### **Login Page**

```javascript
const handleLogin = async (email, password) => {
  const response = await fetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  
  const data = await response.json();
  
  // Store token
  localStorage.setItem('token', data.token);
  localStorage.setItem('role', data.role);
  localStorage.setItem('permissions', JSON.stringify(data.permissions));
  
  // Redirect based on role
  if (data.role === 'SUPER_ADMIN_HELPER') {
    window.location.href = '/tickets';  // IT Support dashboard
  } else if (data.role === 'ORG_HR') {
    window.location.href = '/dashboard';
  }
};
```

### **Tickets Dashboard**

```javascript
const TicketsDashboard = () => {
  const [tickets, setTickets] = useState([]);
  
  useEffect(() => {
    const fetchTickets = async () => {
      const response = await fetch('/secure/ticket/list', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      const data = await response.json();
      setTickets(data.tickets);
    };
    
    fetchTickets();
  }, []);
  
  return (
    <div>
      <h1>Support Tickets</h1>
      <table>
        <thead>
          <tr>
            <th>Ticket ID</th>
            <th>Subject</th>
            <th>Category</th>
            <th>Priority</th>
            <th>Status</th>
            <th>Organization</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {tickets.map(ticket => (
            <tr key={ticket.ticketId}>
              <td>{ticket.ticketId}</td>
              <td>{ticket.subject}</td>
              <td>{ticket.category}</td>
              <td>{ticket.priority}</td>
              <td>{ticket.status}</td>
              <td>{ticket.organizationName}</td>
              <td>
                <button onClick={() => viewTicket(ticket.ticketId)}>
                  View
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
```

---

## **Summary**

### **Quick Answer to Your Question:**

**Q: Do emails in GLOBAL_TEAM_EMAILS need user records?**

**A: Depends on what you want:**

| Scenario | Need User Account? | Schema |
|----------|-------------------|--------|
| Just receive email notifications | ❌ NO | N/A |
| Login and manage tickets in UI | ✅ YES | See schema above |

### **Recommended Setup:**

1. ✅ Add emails to `GLOBAL_TEAM_EMAILS` (for notifications)
2. ✅ Create user accounts with same emails (for UI access)
3. ✅ Use `SUPER_ADMIN_HELPER` role with `accessibleOrganizations`
4. ✅ Grant permissions: `ticket:view`, `ticket:update`, `ticket:comment`

This gives you:
- Email notifications when tickets created
- Full UI access to view and manage tickets
- Role-based filtering (only see assigned orgs)
- Audit trail (who updated what)

