# Complete Ticket System Pipeline Test

## **Base URL**
```
http://localhost:5001
```

---

## **PHASE 1: Setup Users**

### **Step 1.1: Login as SUPER_ADMIN**

```http
POST http://localhost:5001/auth/login
Content-Type: application/json

{
  "email": "admin@bgvapp.in",
  "password": "your_password"
}
```

**Save:** `SUPER_ADMIN_TOKEN` from response

---

### **Step 1.2: Get Your BGV Organization ID**

```http
GET http://localhost:5001/secure/getOrganizations
Authorization: Bearer <SUPER_ADMIN_TOKEN>
```

**Find and save:** BGV organization ID (e.g., `"6924c2f2d126438..."`)

---

### **Step 1.3: Create IT Support User**

```http
POST http://localhost:5001/secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "userName": "IT Support Team",
  "email": "it-support@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+1111111111",
  "organizationId": "YOUR_BGV_ORG_ID",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "ticket:reassign",
    "dashboard:view"
  ],
  "accessibleOrganizations": ["YOUR_CLIENT_ORG_ID"]
}
```

**Expected Response:**
```json
{
  "message": "Helper user added successfully",
  "helper": {
    "userId": "...",
    "email": "it-support@bgvapp.in",
    "defaultPassword": "Welcome1"
  }
}
```

---

### **Step 1.4: Create Verification Support User**

```http
POST http://localhost:5001/secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "userName": "Verification Support",
  "email": "verification@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+2222222222",
  "organizationId": "YOUR_BGV_ORG_ID",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "verification:view",
    "dashboard:view"
  ],
  "accessibleOrganizations": ["YOUR_CLIENT_ORG_ID"]
}
```

---

### **Step 1.5: Create General Support User**

```http
POST http://localhost:5001/secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "userName": "General Support",
  "email": "support@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+3333333333",
  "organizationId": "YOUR_BGV_ORG_ID",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "dashboard:view"
  ],
  "accessibleOrganizations": ["YOUR_CLIENT_ORG_ID"]
}
```

---

## **PHASE 2: Get Ticket Categories**

### **Step 2.1: View Available Categories**

```http
GET http://localhost:5001/secure/ticket/categories
Authorization: Bearer <ANY_TOKEN>
```

**Expected Response:**
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
    {
      "value": "VERIFICATION_ISSUE",
      "label": "Verification Problem",
      "description": "Issues with background verification checks",
      "priority": "MEDIUM",
      "sla_hours": 24
    }
    // ... more categories
  ]
}
```

---

## **PHASE 3: Create Tickets**

### **Step 3.1: Login as ORG_HR**

```http
POST http://localhost:5001/auth/login
Content-Type: application/json

{
  "email": "tulasikillani07@gmail.com",
  "password": "your_password"
}
```

**Save:** `ORG_HR_TOKEN`

---

### **Step 3.2: Create IT Issue Ticket**

```http
POST http://localhost:5001/secure/ticket/create
Authorization: Bearer <ORG_HR_TOKEN>
Content-Type: application/json

{
  "subject": "Cannot login to system",
  "description": "I'm getting a 401 error when trying to login with my credentials. I've tried resetting my password but still can't access the system. This is urgent as I need to process verifications today.",
  "category": "IT_ISSUE",
  "priority": "HIGH",
  "attachments": []
}
```

**Expected Response:**
```json
{
  "message": "Ticket created successfully",
  "ticketId": "TKT-20241129120530-1234",
  "assignedTo": "IT Support Team",
  "slaDeadline": "2024-11-29T15:05:30Z",
  "ticket": {
    "_id": "...",
    "ticketId": "TKT-20241129120530-1234",
    "subject": "Cannot login to system",
    "category": "IT_ISSUE",
    "priority": "HIGH",
    "status": "OPEN",
    "assignedToEmail": "it-support@bgvapp.in"
  }
}
```

**Save:** `TICKET_ID_1` = `"TKT-20241129120530-1234"`

---

### **Step 3.3: Create Verification Issue Ticket**

```http
POST http://localhost:5001/secure/ticket/create
Authorization: Bearer <ORG_HR_TOKEN>
Content-Type: application/json

{
  "subject": "Candidate verification stuck",
  "description": "Verification for candidate John Doe (ID: CAND123) has been stuck in 'IN_PROGRESS' status for 3 days. The primary stage checks are not completing. Please investigate.",
  "category": "VERIFICATION_ISSUE",
  "priority": "MEDIUM",
  "attachments": []
}
```

**Save:** `TICKET_ID_2`

---

### **Step 3.4: Create HR Query Ticket**

```http
POST http://localhost:5001/secure/ticket/create
Authorization: Bearer <ORG_HR_TOKEN>
Content-Type: application/json

{
  "subject": "Question about onboarding process",
  "description": "What documents are required for new employee onboarding? Also, how long does the background verification typically take?",
  "category": "HR_QUERY",
  "priority": "LOW",
  "attachments": []
}
```

**Save:** `TICKET_ID_3`

---

### **Step 3.5: Create Critical Ticket**

```http
POST http://localhost:5001/secure/ticket/create
Authorization: Bearer <ORG_HR_TOKEN>
Content-Type: application/json

{
  "subject": "URGENT: System completely down",
  "description": "The entire BGV system is down. No one can login or access any features. This is affecting all our operations. Need immediate attention!",
  "category": "IT_ISSUE",
  "priority": "CRITICAL",
  "attachments": []
}
```

**Save:** `TICKET_ID_4`
**Note:** This will be assigned to SUPER_SPOC (auto-escalation)

---

## **PHASE 4: View Tickets (Different Roles)**


### **Step 4.1: View Tickets as ORG_HR**

```http
GET http://localhost:5001/secure/ticket/list
Authorization: Bearer <ORG_HR_TOKEN>
```

**Expected:** See all 4 tickets (from your organization)

---

### **Step 4.2: Login as IT Support**

```http
POST http://localhost:5001/auth/login
Content-Type: application/json

{
  "email": "it-support@bgvapp.in",
  "password": "Welcome1"
}
```

**Save:** `IT_SUPPORT_TOKEN`

---

### **Step 4.3: View Tickets as IT Support**

```http
GET http://localhost:5001/secure/ticket/list
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Expected:** See only IT_ISSUE tickets (TICKET_ID_1 and TICKET_ID_4)
**Should NOT see:** VERIFICATION_ISSUE or HR_QUERY tickets

---

### **Step 4.4: View Only Assigned to IT Support**

```http
GET http://localhost:5001/secure/ticket/list?assignedToMe=true
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Expected:** See tickets assigned to `it-support@bgvapp.in`

---

### **Step 4.5: Filter by Status**

```http
GET http://localhost:5001/secure/ticket/list?status=OPEN
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Expected:** See only OPEN tickets

---

### **Step 4.6: Filter by Priority**

```http
GET http://localhost:5001/secure/ticket/list?priority=HIGH
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Expected:** See only HIGH priority tickets

---

### **Step 4.7: Combined Filters**

```http
GET http://localhost:5001/secure/ticket/list?assignedToMe=true&status=OPEN&priority=HIGH
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Expected:** See HIGH priority OPEN tickets assigned to IT Support

---

## **PHASE 5: Get Single Ticket Details**

### **Step 5.1: Get Ticket Details**

```http
GET http://localhost:5001/secure/ticket/TKT-20241129120530-1234
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Expected Response:**
```json
{
  "_id": "...",
  "ticketId": "TKT-20241129120530-1234",
  "subject": "Cannot login to system",
  "description": "I'm getting a 401 error...",
  "category": "IT_ISSUE",
  "priority": "HIGH",
  "status": "OPEN",
  "createdBy": "tulasikillani07@gmail.com",
  "createdByName": "Tulasi Killani",
  "createdByRole": "ORG_HR",
  "organizationName": "Your Org Name",
  "assignedToEmail": "it-support@bgvapp.in",
  "assignedToName": "IT Support Team",
  "comments": [],
  "statusHistory": [
    {
      "status": "OPEN",
      "changedBy": "tulasikillani07@gmail.com",
      "changedAt": "2024-11-29T12:05:30Z",
      "comment": "Ticket created"
    }
  ],
  "slaDeadline": "2024-11-29T15:05:30Z",
  "createdAt": "2024-11-29T12:05:30Z"
}
```

---

## **PHASE 6: Update Ticket Status**

### **Step 6.1: Start Working (OPEN → IN_PROGRESS)**

```http
PUT http://localhost:5001/secure/ticket/TKT-20241129120530-1234/status
Authorization: Bearer <IT_SUPPORT_TOKEN>
Content-Type: application/json

{
  "status": "IN_PROGRESS",
  "comment": "Investigating the login issue. Checking authentication logs and user account status."
}
```

**Expected Response:**
```json
{
  "message": "Ticket status updated successfully"
}
```

---

### **Step 6.2: Verify Status Changed**

```http
GET http://localhost:5001/secure/ticket/TKT-20241129120530-1234
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Expected:** 
- `status: "IN_PROGRESS"`
- New entry in `statusHistory`

---

## **PHASE 7: Add Comments**

### **Step 7.1: Add Progress Comment**

```http
POST http://localhost:5001/secure/ticket/TKT-20241129120530-1234/comment
Authorization: Bearer <IT_SUPPORT_TOKEN>
Content-Type: application/json

{
  "comment": "Found the issue - user's account was locked due to 5 failed login attempts. Unlocking the account now."
}
```

**Expected Response:**
```json
{
  "message": "Comment added successfully",
  "comment": {
    "comment": "Found the issue...",
    "commentedBy": "it-support@bgvapp.in",
    "commentedByName": "IT Support Team",
    "commentedByRole": "SUPER_ADMIN_HELPER",
    "commentedAt": "2024-11-29T12:30:00Z"
  }
}
```

---

### **Step 7.2: Add Another Comment**

```http
POST http://localhost:5001/secure/ticket/TKT-20241129120530-1234/comment
Authorization: Bearer <IT_SUPPORT_TOKEN>
Content-Type: application/json

{
  "comment": "Account unlocked. Verified user can now login successfully."
}
```

---

### **Step 7.3: Verify Comments Added**

```http
GET http://localhost:5001/secure/ticket/TKT-20241129120530-1234
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Expected:** See 2 comments in `comments` array

---

## **PHASE 8: Resolve Ticket**

### **Step 8.1: Mark as RESOLVED**

```http
PUT http://localhost:5001/secure/ticket/TKT-20241129120530-1234/status
Authorization: Bearer <IT_SUPPORT_TOKEN>
Content-Type: application/json

{
  "status": "RESOLVED",
  "comment": "Issue resolved successfully",
  "resolution": "User's account was locked due to multiple failed login attempts. Unlocked the account and verified user can now login successfully. Advised user to use password manager to avoid future lockouts."
}
```

**Expected Response:**
```json
{
  "message": "Ticket status updated successfully"
}
```

---

### **Step 8.2: Verify Resolution**

```http
GET http://localhost:5001/secure/ticket/TKT-20241129120530-1234
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Expected:**
- `status: "RESOLVED"`
- `resolvedAt: "2024-11-29T13:00:00Z"`
- `resolution: "User's account was locked..."`

---

## **PHASE 9: Reassign Ticket**

### **Step 9.1: Login as SUPER_ADMIN**

```http
POST http://localhost:5001/auth/login
Content-Type: application/json

{
  "email": "admin@bgvapp.in",
  "password": "your_password"
}
```

**Save:** `SUPER_ADMIN_TOKEN`

---

### **Step 9.2: Reassign Verification Ticket**

```http
PUT http://localhost:5001/secure/ticket/<TICKET_ID_2>/reassign
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "assignedToEmail": "support@bgvapp.in",
  "reason": "Requires general support expertise, not verification-specific"
}
```

**Expected Response:**
```json
{
  "message": "Ticket reassigned successfully"
}
```

---

### **Step 9.3: Verify Reassignment**

```http
GET http://localhost:5001/secure/ticket/<TICKET_ID_2>
Authorization: Bearer <SUPER_ADMIN_TOKEN>
```

**Expected:**
- `assignedToEmail: "support@bgvapp.in"`
- New entry in `statusHistory` with status "REASSIGNED"

---

## **PHASE 10: Test Access Control**

### **Step 10.1: IT Support Cannot See Verification Tickets**

```http
GET http://localhost:5001/secure/ticket/<TICKET_ID_2>
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Expected:** Should NOT see this ticket (it's VERIFICATION_ISSUE)

---

### **Step 10.2: IT Support Cannot Update HR Tickets**

```http
PUT http://localhost:5001/secure/ticket/<TICKET_ID_3>/status
Authorization: Bearer <IT_SUPPORT_TOKEN>
Content-Type: application/json

{
  "status": "IN_PROGRESS",
  "comment": "Working on it"
}
```

**Expected:** `403 Forbidden` - "Only assigned user or admins can update ticket"

---

### **Step 10.3: Login as Verification Support**

```http
POST http://localhost:5001/auth/login
Content-Type: application/json

{
  "email": "verification@bgvapp.in",
  "password": "Welcome1"
}
```

**Save:** `VERIFICATION_SUPPORT_TOKEN`

---

### **Step 10.4: Verification Support Sees Only Verification Tickets**

```http
GET http://localhost:5001/secure/ticket/list
Authorization: Bearer <VERIFICATION_SUPPORT_TOKEN>
```

**Expected:** See only VERIFICATION_ISSUE tickets (TICKET_ID_2)
**Should NOT see:** IT_ISSUE or HR_QUERY tickets

---

## **PHASE 11: Close Ticket**

### **Step 11.1: Mark Ticket as CLOSED**

```http
PUT http://localhost:5001/secure/ticket/TKT-20241129120530-1234/status
Authorization: Bearer <IT_SUPPORT_TOKEN>
Content-Type: application/json

{
  "status": "CLOSED",
  "comment": "Ticket closed after verification with user"
}
```

---

### **Step 11.2: Verify Closed**

```http
GET http://localhost:5001/secure/ticket/TKT-20241129120530-1234
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Expected:** `status: "CLOSED"`

---

## **PHASE 12: Reopen Ticket**

### **Step 12.1: Reopen Closed Ticket**

```http
PUT http://localhost:5001/secure/ticket/TKT-20241129120530-1234/status
Authorization: Bearer <ORG_HR_TOKEN>
Content-Type: application/json

{
  "status": "REOPENED",
  "comment": "Issue has returned. User still cannot login."
}
```

---

### **Step 12.2: Verify Reopened**

```http
GET http://localhost:5001/secure/ticket/TKT-20241129120530-1234
Authorization: Bearer <ORG_HR_TOKEN>
```

**Expected:** `status: "REOPENED"`

---

## **PHASE 13: Test Critical Ticket (Auto-escalation)**

### **Step 13.1: Login as SUPER_SPOC**

```http
POST http://localhost:5001/auth/login
Content-Type: application/json

{
  "email": "your-super-spoc@bgvapp.in",
  "password": "your_password"
}
```

**Save:** `SUPER_SPOC_TOKEN`

---

### **Step 13.2: View Critical Ticket**

```http
GET http://localhost:5001/secure/ticket/<TICKET_ID_4>
Authorization: Bearer <SUPER_SPOC_TOKEN>
```

**Expected:**
- `priority: "CRITICAL"`
- `assignedToEmail: "your-super-spoc@bgvapp.in"` (auto-escalated)
- `slaDeadline`: 2 hours (50% of normal 4 hours)

---

## **PHASE 14: Test Filters**

### **Step 14.1: Filter by Multiple Criteria**

```http
GET http://localhost:5001/secure/ticket/list?status=OPEN&priority=HIGH&category=IT_ISSUE
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Expected:** Only HIGH priority OPEN IT tickets

---

### **Step 14.2: View All Tickets (SUPER_ADMIN)**

```http
GET http://localhost:5001/secure/ticket/list
Authorization: Bearer <SUPER_ADMIN_TOKEN>
```

**Expected:** See ALL tickets from ALL organizations

---

## **Complete Test Checklist**

### **Setup**
- [ ] SUPER_ADMIN login works
- [ ] IT Support user created
- [ ] Verification Support user created
- [ ] General Support user created
- [ ] ORG_HR login works

### **Ticket Creation**
- [ ] IT Issue ticket created
- [ ] Verification Issue ticket created
- [ ] HR Query ticket created
- [ ] Critical ticket created (auto-escalated to SUPER_SPOC)

### **Ticket Viewing**
- [ ] ORG_HR sees all org tickets
- [ ] IT Support sees only IT tickets
- [ ] Verification Support sees only verification tickets
- [ ] `assignedToMe=true` filter works
- [ ] Status filter works
- [ ] Priority filter works
- [ ] Combined filters work

### **Ticket Management**
- [ ] Get single ticket details works
- [ ] Update status to IN_PROGRESS works
- [ ] Add comment works
- [ ] Resolve ticket works
- [ ] Close ticket works
- [ ] Reopen ticket works

### **Reassignment**
- [ ] SUPER_ADMIN can reassign tickets
- [ ] Reassigned ticket shows new assignee
- [ ] Status history shows reassignment

### **Access Control**
- [ ] IT Support cannot see verification tickets
- [ ] IT Support cannot update HR tickets
- [ ] Verification Support sees only verification tickets
- [ ] ORG_HR sees only own org tickets

### **Auto-escalation**
- [ ] CRITICAL priority tickets assigned to SUPER_SPOC
- [ ] SLA deadline reduced for CRITICAL (2 hours instead of 4)

---

## **Expected Results Summary**

| User | Can See | Can Update | Cannot See |
|------|---------|------------|------------|
| **SUPER_ADMIN** | All tickets | All tickets | N/A |
| **SUPER_SPOC** | All tickets | All tickets | N/A |
| **IT Support** | IT tickets only | IT tickets only | Verification, HR tickets |
| **Verification Support** | Verification tickets | Verification tickets | IT, HR tickets |
| **General Support** | All categories | All tickets | N/A |
| **ORG_HR** | Own org tickets | Own org tickets | Other org tickets |
| **HELPER** | Own created tickets | None | All other tickets |

---

## **Quick Copy-Paste Test Script**

Save this as a file and run through it:

```bash
# 1. Login as SUPER_ADMIN
# 2. Create IT Support user
# 3. Login as ORG_HR
# 4. Create IT ticket
# 5. Login as IT Support
# 6. View tickets (should see only IT tickets)
# 7. Update ticket to IN_PROGRESS
# 8. Add comment
# 9. Resolve ticket
# 10. Login as SUPER_ADMIN
# 11. Reassign ticket
# 12. Verify reassignment worked
```

All done! 🎉
