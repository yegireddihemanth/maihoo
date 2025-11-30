# Quick Test Payloads - Copy & Paste Ready

## **1. Create Support Staff Users**

### **IT Support**
```json
POST /secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>

{
  "userName": "IT Support Team",
  "email": "it-support@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+1111111111",
  "organizationId": "REPLACE_WITH_BGV_ORG_ID",
  "permissions": ["ticket:view", "ticket:update", "ticket:comment", "ticket:reassign"],
  "accessibleOrganizations": ["REPLACE_ORG1_ID", "REPLACE_ORG2_ID"]
}
```

### **Verification Support**
```json
POST /secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>

{
  "userName": "Verification Support",
  "email": "verification@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+2222222222",
  "organizationId": "REPLACE_WITH_BGV_ORG_ID",
  "permissions": ["ticket:view", "ticket:update", "ticket:comment", "verification:view"],
  "accessibleOrganizations": ["REPLACE_ORG1_ID", "REPLACE_ORG2_ID"]
}
```

### **General Support**
```json
POST /secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>

{
  "userName": "General Support",
  "email": "support@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+3333333333",
  "organizationId": "REPLACE_WITH_BGV_ORG_ID",
  "permissions": ["ticket:view", "ticket:update", "ticket:comment"],
  "accessibleOrganizations": ["REPLACE_ORG1_ID", "REPLACE_ORG2_ID"]
}
```

---

## **2. Create Tickets**

### **IT Issue (High Priority)**
```json
POST /secure/ticket/create
Authorization: Bearer <ANY_USER_TOKEN>

{
  "subject": "Cannot login to system",
  "description": "Getting 401 error when trying to login. Tried password reset but still can't access.",
  "category": "IT_ISSUE",
  "priority": "HIGH",
  "attachments": []
}
```

### **Verification Issue**
```json
POST /secure/ticket/create
Authorization: Bearer <ANY_USER_TOKEN>

{
  "subject": "Candidate verification stuck",
  "description": "Verification for candidate ID CAND123 stuck in IN_PROGRESS for 3 days.",
  "category": "VERIFICATION_ISSUE",
  "priority": "MEDIUM",
  "attachments": []
}
```

### **HR Query**
```json
POST /secure/ticket/create
Authorization: Bearer <ANY_USER_TOKEN>

{
  "subject": "Question about onboarding",
  "description": "What documents are required for new employee onboarding?",
  "category": "HR_QUERY",
  "priority": "LOW",
  "attachments": []
}
```

### **Critical Issue (Auto-escalates)**
```json
POST /secure/ticket/create
Authorization: Bearer <ANY_USER_TOKEN>

{
  "subject": "URGENT: System completely down",
  "description": "Entire system is down. No one can login. Need immediate attention!",
  "category": "IT_ISSUE",
  "priority": "CRITICAL",
  "attachments": []
}
```

---

## **3. Manage Tickets**

### **Update Status to IN_PROGRESS**
```json
PUT /secure/ticket/TKT-XXXXXX/status
Authorization: Bearer <SUPPORT_TOKEN>

{
  "status": "IN_PROGRESS",
  "comment": "Investigating the issue. Checking logs."
}
```

### **Add Comment**
```json
POST /secure/ticket/TKT-XXXXXX/comment
Authorization: Bearer <SUPPORT_TOKEN>

{
  "comment": "Found the root cause. Working on a fix."
}
```

### **Resolve Ticket**
```json
PUT /secure/ticket/TKT-XXXXXX/status
Authorization: Bearer <SUPPORT_TOKEN>

{
  "status": "RESOLVED",
  "comment": "Issue fixed",
  "resolution": "User account was locked. Unlocked and verified login works."
}
```

### **Reassign Ticket**
```json
PUT /secure/ticket/TKT-XXXXXX/reassign
Authorization: Bearer <ADMIN_TOKEN>

{
  "assignedToEmail": "support@bgvapp.in",
  "reason": "Requires general support expertise"
}
```

---

## **4. View Tickets**

### **All Tickets (filtered by role)**
```
GET /secure/ticket/list
Authorization: Bearer <TOKEN>
```

### **Only Assigned to Me**
```
GET /secure/ticket/list?assignedToMe=true
Authorization: Bearer <TOKEN>
```

### **Filter by Status**
```
GET /secure/ticket/list?status=OPEN
Authorization: Bearer <TOKEN>
```

### **Filter by Priority**
```
GET /secure/ticket/list?priority=HIGH
Authorization: Bearer <TOKEN>
```

### **Combined Filters**
```
GET /secure/ticket/list?assignedToMe=true&status=OPEN&priority=HIGH
Authorization: Bearer <TOKEN>
```

---

## **5. Login Credentials**

### **IT Support**
```json
POST /auth/login

{
  "email": "it-support@bgvapp.in",
  "password": "Welcome1"
}
```

### **Verification Support**
```json
POST /auth/login

{
  "email": "verification@bgvapp.in",
  "password": "Welcome1"
}
```

### **General Support**
```json
POST /auth/login

{
  "email": "support@bgvapp.in",
  "password": "Welcome1"
}
```

---

## **Quick Test Flow**

1. **Login as SUPER_ADMIN** → Get token
2. **Create IT Support user** → Use payload above
3. **Create test organization** (if needed)
4. **Login as ORG_HR** → Get token
5. **Create IT ticket** → Use IT Issue payload
6. **Check email** → Should receive notification
7. **Login as IT Support** → Get token
8. **View tickets** → `GET /secure/ticket/list`
9. **Update ticket** → Use IN_PROGRESS payload
10. **Resolve ticket** → Use RESOLVED payload
11. **Check email** → Creator should receive updates

---

## **Email Configuration**

Edit `maihoo/utils/ticket_utils.py` line 30:

```python
GLOBAL_TEAM_EMAILS = {
    "IT_TEAM": ["it-support@bgvapp.in", "YOUR_EMAIL@gmail.com"],
    "VERIFICATION_TEAM": ["verification@bgvapp.in", "YOUR_EMAIL@gmail.com"],
    "SUPPORT_TEAM": ["support@bgvapp.in", "YOUR_EMAIL@gmail.com"]
}
```

Replace `YOUR_EMAIL@gmail.com` with your actual email to receive test notifications.

---

## **Expected Results**

### **After Creating IT Ticket:**
- ✅ Ticket created with status OPEN
- ✅ Assigned to IT Support
- ✅ Email sent to `it-support@bgvapp.in`
- ✅ Email sent to team (your email)
- ✅ SLA deadline calculated (3 hours for HIGH priority IT issue)

### **After IT Support Views Tickets:**
- ✅ Sees only IT_ISSUE tickets
- ✅ Does NOT see VERIFICATION_ISSUE or HR_QUERY tickets
- ✅ Can filter by assignedToMe, status, priority

### **After Updating Ticket:**
- ✅ Status changed to IN_PROGRESS
- ✅ Email sent to ticket creator
- ✅ Comment added to ticket history

### **After Resolving Ticket:**
- ✅ Status changed to RESOLVED
- ✅ resolvedAt timestamp set
- ✅ Email sent to creator with resolution
- ✅ Ticket removed from "Open" list

