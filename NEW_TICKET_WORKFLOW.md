# NEW Ticket Management Workflow

## **Complete Workflow Change**

### **OLD Workflow (Removed):**
```
ORG_HR creates ticket → Direct assignment to IT team → IT team works on it
```

### **NEW Workflow (Implemented):**
```
ORG_HR/HELPER creates ticket 
    ↓
ALWAYS assigned to SUPER_ADMIN or SUPER_SPOC
    ↓
SUPER_ADMIN/SUPER_SPOC reviews and reassigns to appropriate team
    ↓
Team member (SUPER_ADMIN_HELPER) works on ticket
```

---

## **Step-by-Step Process**

### **Step 1: Ticket Creation**

**Who:** ORG_HR, HELPER, SPOC  
**Result:** Ticket ALWAYS assigned to SUPER_ADMIN or SUPER_SPOC (preferably SUPER_SPOC)

```http
POST /secure/ticket/create
Authorization: Bearer <ORG_HR_TOKEN>

{
  "subject": "Cannot login to system",
  "category": "IT_ISSUE",
  "priority": "HIGH"
}
```

**Response:**
```json
{
  "ticketId": "TKT-xxx",
  "assignedTo": "SUPER_SPOC",
  "assignedToEmail": "murthi@maihoo.com"
}
```

---

### **Step 2: Admin Review & Reassignment**

**Who:** SUPER_ADMIN or SUPER_SPOC  
**Action:** Review ticket and reassign to appropriate team member

```http
PUT /secure/ticket/TKT-xxx/reassign
Authorization: Bearer <SUPER_ADMIN_TOKEN>

{
  "assignedToEmail": "hemanthdevapple@gmail.com",
  "reason": "IT issue - assigning to IT support team"
}
```

---

### **Step 3: Team Member Works on Ticket**

**Who:** Assigned SUPER_ADMIN_HELPER (IT team, Verification team, etc.)

```http
# Update status
PUT /secure/ticket/TKT-xxx/status
Authorization: Bearer <IT_SUPPORT_TOKEN>

{
  "status": "IN_PROGRESS",
  "comment": "Working on the login issue"
}

# Add comments
POST /secure/ticket/TKT-xxx/comment
Authorization: Bearer <IT_SUPPORT_TOKEN>

{
  "comment": "Found the issue - account was locked"
}

# Resolve
PUT /secure/ticket/TKT-xxx/status
Authorization: Bearer <IT_SUPPORT_TOKEN>

{
  "status": "RESOLVED",
  "resolution": "Unlocked user account"
}
```

---

## **Assignment Logic Changes**

### **Before (Old):**
```python
if category == "IT_ISSUE":
    # Find IT support with org access
    return random_it_support_user

if category == "VERIFICATION_ISSUE":
    # Find verification support
    return random_verification_user
```

### **After (New):**
```python
# ALL tickets go to SUPER_ADMIN/SUPER_SPOC first
superUsers = find_super_users()
if superSpoc_available:
    return superSpoc
else:
    return superAdmin
```

---

## **Authorization Matrix**

### **Who Can Comment:**

| Role | Can Comment | Condition |
|------|-------------|-----------|
| **SUPER_ADMIN** | ✅ | Any ticket |
| **SUPER_SPOC** | ✅ | Any ticket |
| **Ticket Creator** | ✅ | Tickets they created |
| **Assigned User** | ✅ | Tickets assigned to them |
| **ORG_HR/SPOC** | ✅ | Tickets from their org |
| **Other Users** | ❌ | Cannot comment |

---

### **Who Can Update Status:**

| Role | Can Update | Condition |
|------|------------|-----------|
| **SUPER_ADMIN** | ✅ | Any ticket |
| **SUPER_SPOC** | ✅ | Any ticket |
| **Assigned User** | ✅ | Only tickets assigned to them |
| **ORG_HR/SPOC** | ✅ | Tickets from their org |
| **Other Users** | ❌ | Cannot update |

---

### **Who Can Reassign:**

| Role | Can Reassign | Condition |
|------|--------------|-----------|
| **SUPER_ADMIN** | ✅ | Any ticket |
| **SUPER_SPOC** | ✅ | Any ticket |
| **SPOC** | ✅ | Tickets from their org |
| **ORG_HR** | ✅ | Tickets from their org |
| **Other Users** | ❌ | Cannot reassign |

---

## **Example Workflow**

### **Scenario: ORG_HR Reports Login Issue**

**Step 1: Create Ticket**
```bash
# ORG_HR creates ticket
POST /secure/ticket/create
{
  "subject": "Cannot login",
  "category": "IT_ISSUE",
  "priority": "HIGH"
}

# Result: Assigned to SUPER_SPOC (murthi@maihoo.com)
```

**Step 2: SUPER_SPOC Reviews**
```bash
# SUPER_SPOC logs in and sees new ticket
GET /secure/ticket/list

# SUPER_SPOC decides it's an IT issue and reassigns
PUT /secure/ticket/TKT-xxx/reassign
{
  "assignedToEmail": "hemanthdevapple@gmail.com",
  "reason": "IT login issue - assigning to IT support"
}

# Email sent to hemanthdevapple@gmail.com
```

**Step 3: IT Support Works**
```bash
# IT support logs in and sees assigned ticket
GET /secure/ticket/list?assignedToMe=true

# Start working
PUT /secure/ticket/TKT-xxx/status
{
  "status": "IN_PROGRESS",
  "comment": "Investigating login issue"
}

# Add progress comment
POST /secure/ticket/TKT-xxx/comment
{
  "comment": "Found that user account was locked"
}

# Resolve
PUT /secure/ticket/TKT-xxx/status
{
  "status": "RESOLVED",
  "resolution": "Unlocked user account and verified login works"
}
```

**Step 4: ORG_HR Can Comment**
```bash
# Original creator can add comment
POST /secure/ticket/TKT-xxx/comment
Authorization: Bearer <ORG_HR_TOKEN>

{
  "comment": "Thank you! Login is working now."
}
```

---

## **Benefits of New Workflow**

### **✅ Advantages:**
1. **Central Control** - SUPER_ADMIN/SUPER_SPOC reviews all tickets
2. **Proper Routing** - Admin decides which team handles each ticket
3. **Quality Control** - Admin can reject/redirect inappropriate tickets
4. **Load Balancing** - Admin can distribute work evenly
5. **Escalation Path** - Clear hierarchy for complex issues

### **❌ Potential Concerns:**
1. **Bottleneck** - All tickets go through admin first
2. **Delay** - Extra step before work begins
3. **Admin Workload** - More work for SUPER_ADMIN/SUPER_SPOC

---

## **Email Notifications**

### **Ticket Creation:**
- ✅ Email to SUPER_ADMIN/SUPER_SPOC (assignee)
- ✅ Email to team (IT_TEAM, VERIFICATION_TEAM, etc.) for awareness

### **Reassignment:**
- ✅ Email to new assignee (team member)
- ✅ Activity logged

### **Status Updates:**
- ✅ Email to ticket creator
- ✅ Activity logged

---

## **Testing the New Workflow**

### **Test 1: Create Ticket as ORG_HR**
```bash
POST /secure/ticket/create
Authorization: Bearer <ORG_HR_TOKEN>

{
  "subject": "Test ticket",
  "category": "IT_ISSUE",
  "priority": "MEDIUM"
}

# Expected: Assigned to SUPER_SPOC or SUPER_ADMIN
```

### **Test 2: SUPER_SPOC Reassigns**
```bash
PUT /secure/ticket/TKT-xxx/reassign
Authorization: Bearer <SUPER_SPOC_TOKEN>

{
  "assignedToEmail": "hemanthdevapple@gmail.com",
  "reason": "IT issue"
}

# Expected: Success, email sent to IT support
```

### **Test 3: IT Support Works on Ticket**
```bash
# Login as IT support
POST /auth/login
{ "email": "hemanthdevapple@gmail.com", "password": "Welcome1" }

# View assigned tickets
GET /secure/ticket/list?assignedToMe=true

# Expected: See the reassigned ticket
```

### **Test 4: Comment Authorization**
```bash
# IT support adds comment
POST /secure/ticket/TKT-xxx/comment
Authorization: Bearer <IT_SUPPORT_TOKEN>
{ "comment": "Working on it" }
# Expected: Success

# Random user tries to comment
POST /secure/ticket/TKT-xxx/comment
Authorization: Bearer <RANDOM_USER_TOKEN>
{ "comment": "Test" }
# Expected: 403 Forbidden
```

---

## **Summary of Changes**

| Aspect | Old Behavior | New Behavior |
|--------|--------------|--------------|
| **Assignment** | Direct to team | Always to SUPER_ADMIN/SUPER_SPOC first |
| **Team Access** | Automatic | Manual reassignment by admin |
| **Comments** | Anyone with org access | Only creator, assignee, org admins |
| **Status Updates** | Team + org users | Only assignee + admins |
| **Workflow** | Automatic | Manual admin control |

The new workflow gives complete control to SUPER_ADMIN/SUPER_SPOC for ticket routing and management! 🚀
