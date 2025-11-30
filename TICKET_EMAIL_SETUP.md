# Ticket System Email & Access Setup Guide

## **Email Flow Architecture**

### **1. Where Emails Come From**

```
┌─────────────────────────────────────────────────────────┐
│                    EMAIL SOURCES                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  A) ASSIGNEE EMAIL (from users DB)                     │
│     ↓                                                   │
│     MongoDB users collection                            │
│     { email: "john@company.com", role: "ORG_HR" }      │
│                                                         │
│  B) TEAM EMAILS (2 options)                            │
│     ↓                                                   │
│     Option 1: Global (hardcoded in ticket_utils.py)    │
│     Option 2: Per-org (stored in organizations DB)     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## **2. Setup Options**

### **Option A: Centralized Support (Simple)**

**Use Case:** Small setup, one BGV team handles all organizations

**Setup:**
1. Edit `maihoo/utils/ticket_utils.py` (line 30-40)
2. Update `GLOBAL_TEAM_EMAILS`:

```python
GLOBAL_TEAM_EMAILS = {
    "IT_TEAM": ["your-it@bgvapp.in", "tech-support@bgvapp.in"],
    "VERIFICATION_TEAM": ["verification@bgvapp.in"],
    "HR_TEAM": ["hr@bgvapp.in"],
    "FINANCE_TEAM": ["finance@bgvapp.in"],
    "PRODUCT_TEAM": ["product@bgvapp.in"],
    "DEV_TEAM": ["dev@bgvapp.in"],
    "SUPPORT_TEAM": ["support@bgvapp.in"]
}
```

**Flow:**
```
User creates ticket (IT_ISSUE)
    ↓
System assigns to IT_SUPPORT user (from users DB)
    ↓
Sends email to:
  1. Assignee: john@bgvapp.in (from users DB)
  2. IT Team: your-it@bgvapp.in, tech-support@bgvapp.in (from config)
```

**Pros:**
- ✅ Simple setup
- ✅ One team for all orgs
- ✅ No database changes needed

**Cons:**
- ❌ Can't have org-specific teams
- ❌ Need code change to update emails

---

### **Option B: Per-Organization Support (Scalable)**

**Use Case:** Large setup, each org has their own IT/support team

**Setup:**

#### **Step 1: Add Support Teams to Organization Document**

When creating/updating an organization, add `supportTeams` field:

```javascript
// Example organization document
{
  "_id": ObjectId("org123"),
  "organizationName": "Acme Corp",
  "email": "admin@acme.com",
  
  // NEW FIELD: Organization-specific support teams
  "supportTeams": {
    "IT_TEAM": ["it@acme.com", "tech@acme.com"],
    "VERIFICATION_TEAM": ["bgv@acme.com"],
    "HR_TEAM": ["hr@acme.com"],
    "FINANCE_TEAM": ["finance@acme.com"],
    "SUPPORT_TEAM": ["support@acme.com"]
  },
  
  // ... rest of org fields
}
```

#### **Step 2: Update Organization via API**

```http
PUT /secure/updateOrganization/org123
Authorization: Bearer <token>
Content-Type: application/json

{
  "supportTeams": {
    "IT_TEAM": ["it@acme.com", "tech@acme.com"],
    "VERIFICATION_TEAM": ["bgv@acme.com"],
    "HR_TEAM": ["hr@acme.com"],
    "SUPPORT_TEAM": ["support@acme.com"]
  }
}
```

#### **Step 3: System Automatically Uses Org Teams**

```
User from Acme Corp creates IT ticket
    ↓
System checks: Does Acme have supportTeams.IT_TEAM?
    ↓ YES
Sends to: it@acme.com, tech@acme.com
    ↓ NO (fallback)
Sends to: it-support@bgvapp.in (global team)
```

**Flow Diagram:**
```
┌──────────────────────────────────────────────────┐
│  User creates ticket (IT_ISSUE)                 │
│  Organization: Acme Corp                        │
└──────────────────┬───────────────────────────────┘
                   ↓
┌──────────────────────────────────────────────────┐
│  System checks:                                  │
│  orgsCol.findOne({_id: "org123"})               │
│  Does org have supportTeams.IT_TEAM?            │
└──────────────────┬───────────────────────────────┘
                   ↓
         ┌─────────┴─────────┐
         │                   │
    YES  │                   │  NO
         ↓                   ↓
┌─────────────────┐  ┌──────────────────┐
│ Use Org Team    │  │ Use Global Team  │
│ it@acme.com     │  │ it@bgvapp.in     │
└─────────────────┘  └──────────────────┘
```

**Pros:**
- ✅ Each org can have own teams
- ✅ Stored in database (no code changes)
- ✅ Fallback to global team if not configured
- ✅ Scalable for multi-tenant

**Cons:**
- ❌ More complex setup
- ❌ Need to configure per org

---

## **3. Do Support Members Need to Be in Users DB?**

### **Short Answer: NO (for receiving emails)**

Team emails in `supportTeams` are just email addresses. They don't need user accounts.

### **Long Answer: YES (for accessing tickets in UI)**

If support staff want to:
- ✅ Login to system
- ✅ View assigned tickets
- ✅ Update ticket status
- ✅ Add comments

Then they MUST have user accounts in `users` collection.

---

## **4. Recommended User Roles for Support Staff**

### **Option 1: Add New Roles**

```javascript
// Add these roles to your system
{
  "userName": "IT Support Team",
  "email": "it@acme.com",
  "role": "IT_SUPPORT",  // NEW ROLE
  "organizationId": "org123",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment"
  ]
}

{
  "userName": "Verification Specialist",
  "email": "bgv@acme.com",
  "role": "VERIFICATION_SPECIALIST",  // NEW ROLE
  "organizationId": "org123",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "verification:view"
  ]
}
```

### **Option 2: Use Existing Roles**

```javascript
// Use SUPER_ADMIN_HELPER for support staff
{
  "userName": "IT Support",
  "email": "it@acme.com",
  "role": "SUPER_ADMIN_HELPER",
  "organizationId": "bgv_central",  // BGV's own org
  "accessibleOrganizations": ["org123", "org456", "org789"],
  "permissions": [
    "ticket:view",
    "ticket:update",
    "verification:view"
  ]
}
```

---

## **5. Ticket Access in UI**

### **Who Can See Which Tickets?**

```javascript
// GET /secure/ticket/list

// SUPER_ADMIN / SUPER_SPOC
→ Sees ALL tickets from ALL organizations

// SUPER_ADMIN_HELPER (IT Support)
→ Sees tickets from accessibleOrganizations
→ Example: IT support can see tickets from Acme, TechCorp, etc.

// SPOC / ORG_HR
→ Sees tickets from THEIR organization only
→ Example: Acme's HR sees only Acme tickets

// HELPER
→ Sees tickets THEY created only
→ Example: Helper John sees only his own tickets

// IT_SUPPORT (if you add this role)
→ Sees tickets assigned to them
→ Or tickets with category IT_ISSUE (custom logic)
```

### **Frontend Implementation**

#### **A) Ticket List Page**

```javascript
// Fetch tickets (automatically filtered by backend)
const response = await fetch('/secure/ticket/list', {
  headers: { 'Authorization': `Bearer ${token}` }
});

const { tickets } = await response.json();

// Display in table
tickets.forEach(ticket => {
  // Show: ticketId, subject, category, priority, status, assignedTo
});
```

#### **B) Ticket Detail Page**

```javascript
// When user clicks on a ticket
const ticket = await fetch(`/secure/ticket/${ticketId}`, {
  headers: { 'Authorization': `Bearer ${token}` }
}).then(r => r.json());

// Show:
// - Full description
// - Comments
// - Status history
// - Attachments
// - Actions: Update Status, Add Comment, Reassign
```

#### **C) Create Ticket Form**

```javascript
// 1. Fetch categories
const { categories } = await fetch('/secure/ticket/categories', {
  headers: { 'Authorization': `Bearer ${token}` }
}).then(r => r.json());

// 2. Show form
<form onSubmit={handleSubmit}>
  <input name="subject" placeholder="Brief description" />
  <textarea name="description" placeholder="Detailed description" />
  
  <select name="category">
    {categories.map(cat => (
      <option value={cat.value}>{cat.label}</option>
    ))}
  </select>
  
  <select name="priority">
    <option value="LOW">Low</option>
    <option value="MEDIUM">Medium</option>
    <option value="HIGH">High</option>
    <option value="CRITICAL">Critical</option>
  </select>
  
  {/* IT Issue Toggle */}
  <label>
    <input 
      type="checkbox" 
      onChange={(e) => {
        if (e.target.checked) {
          setCategory('IT_ISSUE');
          setPriority('HIGH');
        }
      }}
    />
    This is an IT/Technical issue
  </label>
  
  <button type="submit">Create Ticket</button>
</form>
```

---

## **6. Complete Setup Checklist**

### **For Centralized Support (Simple)**

- [ ] Update `GLOBAL_TEAM_EMAILS` in `ticket_utils.py`
- [ ] Create user accounts for support staff (optional, for UI access)
- [ ] Test ticket creation
- [ ] Verify emails are received

### **For Per-Organization Support (Advanced)**

- [ ] Update `GLOBAL_TEAM_EMAILS` (fallback)
- [ ] Add `supportTeams` field to organization documents
- [ ] Create user accounts for org-specific support staff
- [ ] Assign appropriate roles (IT_SUPPORT, VERIFICATION_SPECIALIST, etc.)
- [ ] Test ticket creation from different orgs
- [ ] Verify org-specific emails are used

---

## **7. Example Scenarios**

### **Scenario 1: Acme Corp has own IT team**

**Setup:**
```javascript
// Organization document
{
  "_id": "org_acme",
  "organizationName": "Acme Corp",
  "supportTeams": {
    "IT_TEAM": ["it@acme.com"]
  }
}

// User account for IT staff
{
  "email": "it@acme.com",
  "role": "IT_SUPPORT",
  "organizationId": "org_acme"
}
```

**Flow:**
1. Acme employee creates IT ticket
2. Email sent to: `it@acme.com` (org-specific)
3. IT staff logs in, sees ticket in UI
4. Updates status to RESOLVED

---

### **Scenario 2: TechCorp has no IT team (uses BGV central)**

**Setup:**
```javascript
// Organization document (no supportTeams)
{
  "_id": "org_techcorp",
  "organizationName": "TechCorp"
  // No supportTeams field
}
```

**Flow:**
1. TechCorp employee creates IT ticket
2. System checks: No org-specific IT team
3. Falls back to global: `it-support@bgvapp.in`
4. BGV central IT team handles it

---

### **Scenario 3: BGV IT Support handles multiple orgs**

**Setup:**
```javascript
// BGV IT Support user
{
  "email": "it-support@bgvapp.in",
  "role": "SUPER_ADMIN_HELPER",
  "accessibleOrganizations": ["org_acme", "org_techcorp", "org_xyz"]
}
```

**Flow:**
1. IT support logs in
2. Sees tickets from Acme, TechCorp, XYZ
3. Can update any ticket from these orgs
4. Cannot see tickets from other orgs

---

## **8. Database Schema Updates**

### **Organizations Collection**

```javascript
{
  "_id": ObjectId,
  "organizationName": "Acme Corp",
  "email": "admin@acme.com",
  
  // EXISTING FIELDS
  "spocName": "John Doe",
  "mainDomain": "acme.com",
  "subDomain": "acme.bgvapp.in",
  "services": [...],
  "credentials": {...},
  
  // NEW FIELD (optional)
  "supportTeams": {
    "IT_TEAM": ["it@acme.com", "tech@acme.com"],
    "VERIFICATION_TEAM": ["bgv@acme.com"],
    "HR_TEAM": ["hr@acme.com"],
    "FINANCE_TEAM": ["finance@acme.com"],
    "SUPPORT_TEAM": ["support@acme.com"]
  }
}
```

### **Users Collection (Support Staff)**

```javascript
{
  "_id": ObjectId,
  "userName": "IT Support Team",
  "email": "it@acme.com",
  "password": "Welcome1",
  "role": "IT_SUPPORT",  // or SUPER_ADMIN_HELPER
  "organizationId": "org_acme",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "ticket:reassign"
  ],
  "isActive": true
}
```

---

## **9. Quick Start Commands**

### **Add Support Teams to Existing Org**

```bash
# MongoDB shell
db.organizations.updateOne(
  { _id: ObjectId("org123") },
  { 
    $set: { 
      supportTeams: {
        IT_TEAM: ["it@acme.com"],
        SUPPORT_TEAM: ["support@acme.com"]
      }
    }
  }
)
```

### **Create IT Support User**

```bash
# Via API
POST /secure/addHelper
{
  "userName": "IT Support",
  "email": "it@acme.com",
  "role": "SUPER_ADMIN_HELPER",
  "organizationId": "org123",
  "permissions": ["ticket:view", "ticket:update"]
}
```

---

## **10. Testing**

### **Test Email Flow**

```bash
# 1. Create ticket
POST /secure/ticket/create
{
  "subject": "Test IT Issue",
  "description": "Testing email notifications",
  "category": "IT_ISSUE",
  "priority": "HIGH"
}

# 2. Check emails received:
# - Assignee email (from users DB)
# - Team emails (from org supportTeams or global config)

# 3. Verify in logs
# Check console for: "Failed to send notification to..." errors
```

---

## **Summary**

| Question | Answer |
|----------|--------|
| Where do emails come from? | 1) Assignee from `users` DB, 2) Team from org `supportTeams` or global config |
| Do support staff need user accounts? | NO for receiving emails, YES for UI access |
| Does each org need own IT team? | NO - can use global BGV team (fallback) |
| How to configure org-specific teams? | Add `supportTeams` field to organization document |
| How do support staff access tickets? | Login with user account, use `/secure/ticket/list` endpoint |
| Can one IT person handle multiple orgs? | YES - use SUPER_ADMIN_HELPER with `accessibleOrganizations` |

