# Complete Ticket System Testing Guide

## **Prerequisites**

1. ✅ MongoDB running
2. ✅ FastAPI server running (`uvicorn main:app --reload`)
3. ✅ Gmail API configured (for email notifications)
4. ✅ At least one organization created
5. ✅ SUPER_ADMIN user exists

---

## **Step-by-Step Testing**

### **STEP 1: Setup - Create Organizations**

#### **1.1 Login as SUPER_ADMIN**

```http
POST http://localhost:8000/auth/login
Content-Type: application/json

{
  "email": "admin@bgvapp.in",
  "password": "your_password"
}
```

**Save the token from response:**
```json
{
  "token": "eyJhbGc...",
  "role": "SUPER_ADMIN"
}
```

---

#### **1.2 Create Test Organizations**

**Organization 1: Acme Corp**
```http
POST http://localhost:8000/secure/registerOrganization
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "organizationName": "Acme Corp",
  "spocName": "John Doe",
  "mainDomain": "acme.com",
  "subDomain": "acme.bgvapp.in",
  "email": "spoc@acme.com",
  "phone": "+1234567890",
  "gstNumber": "ACME123GST",
  "services": [
    {
      "serviceName": "Background Verification",
      "price": 500.0
    }
  ],
  "credentials": {
    "totalAllowed": 50,
    "used": 0
  }
}
```

**Save:** `organizationId` from response (e.g., `"org_acme_id"`)

---

**Organization 2: TechCorp**
```http
POST http://localhost:8000/secure/registerOrganization
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "organizationName": "TechCorp",
  "spocName": "Jane Smith",
  "mainDomain": "techcorp.com",
  "subDomain": "techcorp.bgvapp.in",
  "email": "spoc@techcorp.com",
  "phone": "+9876543210",
  "gstNumber": "TECH456GST",
  "services": [
    {
      "serviceName": "Background Verification",
      "price": 600.0
    }
  ],
  "credentials": {
    "totalAllowed": 30,
    "used": 0
  }
}
```

**Save:** `organizationId` from response (e.g., `"org_techcorp_id"`)

---

### **STEP 2: Create Support Staff Users**

#### **2.1 Create IT Support User**

```http
POST http://localhost:8000/secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "userName": "IT Support Team",
  "email": "it-support@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+1111111111",
  "organizationId": "<BGV_CENTRAL_ORG_ID>",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "ticket:reassign",
    "dashboard:view"
  ],
  "accessibleOrganizations": [
    "<org_acme_id>",
    "<org_techcorp_id>"
  ]
}
```

**Response:**
```json
{
  "message": "Helper user added successfully",
  "helper": {
    "userId": "user_it_support_id",
    "email": "it-support@bgvapp.in",
    "role": "SUPER_ADMIN_HELPER",
    "defaultPassword": "Welcome1"
  }
}
```

---

#### **2.2 Create Verification Support User**

```http
POST http://localhost:8000/secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "userName": "Verification Support Team",
  "email": "verification@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+2222222222",
  "organizationId": "<BGV_CENTRAL_ORG_ID>",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "verification:view",
    "verification:assign",
    "dashboard:view"
  ],
  "accessibleOrganizations": [
    "<org_acme_id>",
    "<org_techcorp_id>"
  ]
}
```

---

#### **2.3 Create General Support User**

```http
POST http://localhost:8000/secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "userName": "General Support Team",
  "email": "support@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+3333333333",
  "organizationId": "<BGV_CENTRAL_ORG_ID>",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "dashboard:view"
  ],
  "accessibleOrganizations": [
    "<org_acme_id>",
    "<org_techcorp_id>"
  ]
}
```

---

#### **2.4 Create ORG_HR User (for Acme Corp)**

```http
POST http://localhost:8000/secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "userName": "Acme HR Manager",
  "email": "hr@acme.com",
  "password": "Welcome1",
  "role": "ORG_HR",
  "phoneNumber": "+4444444444",
  "organizationId": "<org_acme_id>",
  "permissions": [
    "verification:view",
    "verification:assign",
    "candidate:create",
    "employee:create",
    "ticket:view",
    "ticket:update"
  ]
}
```

---

#### **2.5 Create HELPER User (for Acme Corp)**

```http
POST http://localhost:8000/secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "userName": "Acme Helper",
  "email": "helper@acme.com",
  "password": "Welcome1",
  "role": "HELPER",
  "phoneNumber": "+5555555555",
  "organizationId": "<org_acme_id>",
  "permissions": [
    "verification:view",
    "ticket:view"
  ]
}
```

---

### **STEP 3: Configure Email Notifications**

#### **3.1 Update ticket_utils.py**

Edit `maihoo/utils/ticket_utils.py` (line 30-40):

```python
GLOBAL_TEAM_EMAILS = {
    "IT_TEAM": ["it-support@bgvapp.in", "your-email@gmail.com"],
    "VERIFICATION_TEAM": ["verification@bgvapp.in", "your-email@gmail.com"],
    "HR_TEAM": ["hr@bgvapp.in"],
    "FINANCE_TEAM": ["finance@bgvapp.in"],
    "PRODUCT_TEAM": ["product@bgvapp.in"],
    "DEV_TEAM": ["dev@bgvapp.in"],
    "SUPPORT_TEAM": ["support@bgvapp.in", "your-email@gmail.com"],
    "ESCALATION": ["escalation@bgvapp.in", "admin@bgvapp.in"]
}
```

**Replace `your-email@gmail.com` with your actual email to receive test notifications.**

---

### **STEP 4: Test Ticket Creation**

#### **4.1 Get Available Categories**

```http
GET http://localhost:8000/secure/ticket/categories
Authorization: Bearer <ANY_USER_TOKEN>
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
    {
      "value": "VERIFICATION_ISSUE",
      "label": "Verification Problem",
      "description": "Issues with background verification checks",
      "priority": "MEDIUM",
      "sla_hours": 24
    },
    // ... more categories
  ]
}
```

---

#### **4.2 Create IT Issue Ticket (as ORG_HR)**

**First, login as ORG_HR:**
```http
POST http://localhost:8000/auth/login
Content-Type: application/json

{
  "email": "hr@acme.com",
  "password": "Welcome1"
}
```

**Save token, then create ticket:**
```http
POST http://localhost:8000/secure/ticket/create
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
    "_id": "ticket_id_123",
    "ticketId": "TKT-20241129120530-1234",
    "subject": "Cannot login to system",
    "category": "IT_ISSUE",
    "priority": "HIGH",
    "status": "OPEN",
    "assignedToEmail": "it-support@bgvapp.in",
    "organizationName": "Acme Corp"
  }
}
```

**Expected Emails:**
1. ✅ Email to `it-support@bgvapp.in` (assignee)
2. ✅ Email to `your-email@gmail.com` (team notification)

---

#### **4.3 Create Verification Issue Ticket**

```http
POST http://localhost:8000/secure/ticket/create
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

**Expected:**
- Assigned to: `verification@bgvapp.in`
- Email sent to verification team

---

#### **4.4 Create HR Query Ticket**

```http
POST http://localhost:8000/secure/ticket/create
Authorization: Bearer <ORG_HR_TOKEN>
Content-Type: application/json

{
  "subject": "Question about employee onboarding process",
  "description": "What documents are required for new employee onboarding? Also, how long does the background verification typically take?",
  "category": "HR_QUERY",
  "priority": "LOW",
  "attachments": []
}
```

---

#### **4.5 Create Critical Ticket (Auto-escalates to SUPER_SPOC)**

```http
POST http://localhost:8000/secure/ticket/create
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

**Expected:**
- Assigned to: SUPER_SPOC (highest authority)
- SLA: 2 hours (50% of normal 4 hours)

---

### **STEP 5: Test Support Staff Access**

#### **5.1 Login as IT Support**

```http
POST http://localhost:8000/auth/login
Content-Type: application/json

{
  "email": "it-support@bgvapp.in",
  "password": "Welcome1"
}
```

**Save token:** `<IT_SUPPORT_TOKEN>`

---

#### **5.2 View All IT Tickets**

```http
GET http://localhost:8000/secure/ticket/list
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Expected Response:**
```json
{
  "total": 2,
  "tickets": [
    {
      "ticketId": "TKT-20241129120530-1234",
      "subject": "Cannot login to system",
      "category": "IT_ISSUE",
      "priority": "HIGH",
      "status": "OPEN"
    },
    {
      "ticketId": "TKT-20241129120530-5678",
      "subject": "URGENT: System completely down",
      "category": "IT_ISSUE",
      "priority": "CRITICAL",
      "status": "OPEN"
    }
    // Should NOT see VERIFICATION_ISSUE or HR_QUERY tickets
  ],
  "filters": {
    "role": "SUPER_ADMIN_HELPER"
  }
}
```

---

#### **5.3 View Only Tickets Assigned to Me**

```http
GET http://localhost:8000/secure/ticket/list?assignedToMe=true
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Shows only tickets where `assignedToEmail = "it-support@bgvapp.in"`**

---

#### **5.4 Filter by Status**

```http
GET http://localhost:8000/secure/ticket/list?status=OPEN
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

---

#### **5.5 Combined Filters**

```http
GET http://localhost:8000/secure/ticket/list?assignedToMe=true&status=OPEN&priority=HIGH
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

---

### **STEP 6: Test Ticket Management**

#### **6.1 Get Single Ticket Details**

```http
GET http://localhost:8000/secure/ticket/TKT-20241129120530-1234
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Response:**
```json
{
  "_id": "ticket_id_123",
  "ticketId": "TKT-20241129120530-1234",
  "subject": "Cannot login to system",
  "description": "I'm getting a 401 error...",
  "category": "IT_ISSUE",
  "priority": "HIGH",
  "status": "OPEN",
  "createdBy": "hr@acme.com",
  "createdByName": "Acme HR Manager",
  "organizationName": "Acme Corp",
  "assignedToEmail": "it-support@bgvapp.in",
  "comments": [],
  "statusHistory": [
    {
      "status": "OPEN",
      "changedBy": "hr@acme.com",
      "changedAt": "2024-11-29T12:05:30Z",
      "comment": "Ticket created"
    }
  ],
  "slaDeadline": "2024-11-29T15:05:30Z"
}
```

---

#### **6.2 Update Ticket Status to IN_PROGRESS**

```http
PUT http://localhost:8000/secure/ticket/TKT-20241129120530-1234/status
Authorization: Bearer <IT_SUPPORT_TOKEN>
Content-Type: application/json

{
  "status": "IN_PROGRESS",
  "comment": "Investigating the login issue. Checking authentication logs and user account status."
}
```

**Expected:**
- ✅ Status updated to IN_PROGRESS
- ✅ Email sent to ticket creator (hr@acme.com)

---

#### **6.3 Add Comment**

```http
POST http://localhost:8000/secure/ticket/TKT-20241129120530-1234/comment
Authorization: Bearer <IT_SUPPORT_TOKEN>
Content-Type: application/json

{
  "comment": "Found the issue - user account was locked due to 5 failed login attempts. Unlocking the account now."
}
```

---

#### **6.4 Resolve Ticket**

```http
PUT http://localhost:8000/secure/ticket/TKT-20241129120530-1234/status
Authorization: Bearer <IT_SUPPORT_TOKEN>
Content-Type: application/json

{
  "status": "RESOLVED",
  "comment": "Issue resolved successfully",
  "resolution": "User's account was locked due to multiple failed login attempts. Unlocked the account and verified user can now login successfully. Advised user to use password manager to avoid future lockouts."
}
```

**Expected:**
- ✅ Status updated to RESOLVED
- ✅ `resolvedAt` timestamp set
- ✅ Email sent to creator with resolution

---

#### **6.5 Reassign Ticket (Admin Only)**

**Login as SUPER_ADMIN first:**
```http
POST http://localhost:8000/auth/login
Content-Type: application/json

{
  "email": "admin@bgvapp.in",
  "password": "your_password"
}
```

**Then reassign:**
```http
PUT http://localhost:8000/secure/ticket/TKT-20241129120530-5678/reassign
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "assignedToEmail": "support@bgvapp.in",
  "reason": "Requires general support expertise, not IT-specific"
}
```

**Expected:**
- ✅ Ticket reassigned to `support@bgvapp.in`
- ✅ Email sent to new assignee

---

### **STEP 7: Test Access Control**

#### **7.1 IT Support Cannot See Verification Tickets**

**Login as IT Support:**
```http
GET http://localhost:8000/secure/ticket/list
Authorization: Bearer <IT_SUPPORT_TOKEN>
```

**Should NOT see tickets with `category: "VERIFICATION_ISSUE"`**

---

#### **7.2 IT Support Cannot Update HR Tickets**

**Try to update HR ticket:**
```http
PUT http://localhost:8000/secure/ticket/<HR_TICKET_ID>/status
Authorization: Bearer <IT_SUPPORT_TOKEN>
Content-Type: application/json

{
  "status": "IN_PROGRESS",
  "comment": "Working on it"
}
```

**Expected:** `403 Forbidden` - "Only assigned user or admins can update ticket"

---

#### **7.3 HELPER Can Only See Their Own Tickets**

**Login as HELPER:**
```http
POST http://localhost:8000/auth/login
Content-Type: application/json

{
  "email": "helper@acme.com",
  "password": "Welcome1"
}
```

**View tickets:**
```http
GET http://localhost:8000/secure/ticket/list
Authorization: Bearer <HELPER_TOKEN>
```

**Should only see tickets where `createdBy = "helper@acme.com"`**

---

### **STEP 8: Test Email Notifications**

#### **8.1 Check Your Email Inbox**

After creating tickets, check your email (the one you added to `GLOBAL_TEAM_EMAILS`):

**Expected Emails:**

1. **IT Issue Created:**
   - Subject: `[HIGH] New Ticket: Cannot login to system`
   - Body: Contains ticket details, SLA deadline

2. **Ticket Status Updated:**
   - Subject: `Ticket TKT-xxx Status Updated: IN_PROGRESS`
   - Body: Contains comment from IT support

3. **Ticket Resolved:**
   - Subject: `Ticket TKT-xxx Status Updated: RESOLVED`
   - Body: Contains resolution text

---

## **Complete User Payloads Reference**

### **1. IT Support User**

```json
{
  "userName": "IT Support Team",
  "email": "it-support@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+1111111111",
  "organizationId": "<BGV_CENTRAL_ORG_ID>",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "ticket:reassign",
    "dashboard:view"
  ],
  "accessibleOrganizations": ["<org1_id>", "<org2_id>"]
}
```

---

### **2. Verification Support User**

```json
{
  "userName": "Verification Support Team",
  "email": "verification@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+2222222222",
  "organizationId": "<BGV_CENTRAL_ORG_ID>",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "verification:view",
    "verification:assign",
    "dashboard:view"
  ],
  "accessibleOrganizations": ["<org1_id>", "<org2_id>"]
}
```

---

### **3. General Support User**

```json
{
  "userName": "General Support Team",
  "email": "support@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+3333333333",
  "organizationId": "<BGV_CENTRAL_ORG_ID>",
  "permissions": [
    "ticket:view",
    "ticket:update",
    "ticket:comment",
    "dashboard:view"
  ],
  "accessibleOrganizations": ["<org1_id>", "<org2_id>"]
}
```

---

### **4. ORG_HR User**

```json
{
  "userName": "HR Manager",
  "email": "hr@company.com",
  "password": "Welcome1",
  "role": "ORG_HR",
  "phoneNumber": "+4444444444",
  "organizationId": "<company_org_id>",
  "permissions": [
    "verification:view",
    "verification:assign",
    "candidate:create",
    "employee:create",
    "ticket:view",
    "ticket:update"
  ]
}
```

---

### **5. HELPER User**

```json
{
  "userName": "Helper Name",
  "email": "helper@company.com",
  "password": "Welcome1",
  "role": "HELPER",
  "phoneNumber": "+5555555555",
  "organizationId": "<company_org_id>",
  "permissions": [
    "verification:view",
    "ticket:view"
  ]
}
```

---

### **6. SPOC User**

```json
{
  "userName": "SPOC Name",
  "email": "spoc@company.com",
  "password": "Welcome1",
  "role": "SPOC",
  "phoneNumber": "+6666666666",
  "organizationId": "<company_org_id>",
  "permissions": [
    "organization:view",
    "organization:update",
    "employee:create",
    "verification:view",
    "verification:assign",
    "dashboard:view",
    "users:manage",
    "candidate:create",
    "ticket:view",
    "ticket:update",
    "ticket:reassign"
  ]
}
```

---

## **All Ticket Endpoints Summary**

| Method | Endpoint | Purpose | Auth Required |
|--------|----------|---------|---------------|
| GET | `/secure/ticket/categories` | Get available categories | ✅ Any user |
| POST | `/secure/ticket/create` | Create new ticket | ✅ Any user |
| GET | `/secure/ticket/list` | List tickets (filtered by role) | ✅ Any user |
| GET | `/secure/ticket/{ticketId}` | Get single ticket | ✅ Authorized users |
| PUT | `/secure/ticket/{ticketId}/status` | Update ticket status | ✅ Assignee/Admin |
| POST | `/secure/ticket/{ticketId}/comment` | Add comment | ✅ Creator/Assignee/Admin |
| PUT | `/secure/ticket/{ticketId}/reassign` | Reassign ticket | ✅ Admin only |

---

## **Testing Checklist**

### **Setup**
- [ ] MongoDB running
- [ ] FastAPI server running
- [ ] Gmail API configured
- [ ] At least 2 organizations created
- [ ] Support staff users created (IT, Verification, General)
- [ ] ORG_HR user created
- [ ] HELPER user created
- [ ] Email addresses configured in `GLOBAL_TEAM_EMAILS`

### **Ticket Creation**
- [ ] Create IT issue ticket
- [ ] Create verification issue ticket
- [ ] Create HR query ticket
- [ ] Create critical priority ticket
- [ ] Verify emails received

### **Support Staff Access**
- [ ] IT support sees only IT tickets
- [ ] Verification support sees only verification tickets
- [ ] General support sees all tickets
- [ ] Filter by "assigned to me" works
- [ ] Filter by status works
- [ ] Filter by priority works

### **Ticket Management**
- [ ] Update ticket status to IN_PROGRESS
- [ ] Add comment to ticket
- [ ] Resolve ticket with resolution
- [ ] Reassign ticket (as admin)
- [ ] Verify emails sent on each action

### **Access Control**
- [ ] IT support cannot see verification tickets
- [ ] IT support cannot update HR tickets
- [ ] HELPER only sees their own tickets
- [ ] ORG_HR sees all tickets in their org

---

## **Troubleshooting**

### **No Emails Received**

1. Check Gmail API token is valid (`token.json`)
2. Check `GLOBAL_TEAM_EMAILS` has your email
3. Check console for email errors
4. Verify `send_ticket_email()` function works

### **403 Forbidden Errors**

1. Check user has correct role
2. Check `accessibleOrganizations` includes the org
3. Check ticket category matches user's domain (IT support → IT tickets)

### **Tickets Not Showing**

1. Check user is logged in with correct token
2. Check organization ID matches
3. Check category filtering (IT support only sees IT tickets)
4. Try without filters first: `GET /secure/ticket/list`

---

## **Quick Test Script (Postman Collection)**

Save this as `ticket_tests.postman_collection.json`:

```json
{
  "info": {
    "name": "Ticket System Tests",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "1. Login as SUPER_ADMIN",
      "request": {
        "method": "POST",
        "header": [],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"email\": \"admin@bgvapp.in\",\n  \"password\": \"your_password\"\n}",
          "options": {
            "raw": {
              "language": "json"
            }
          }
        },
        "url": {
          "raw": "http://localhost:8000/auth/login",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8000",
          "path": ["auth", "login"]
        }
      }
    },
    {
      "name": "2. Create IT Support User",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Authorization",
            "value": "Bearer {{admin_token}}",
            "type": "text"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"userName\": \"IT Support Team\",\n  \"email\": \"it-support@bgvapp.in\",\n  \"password\": \"Welcome1\",\n  \"role\": \"SUPER_ADMIN_HELPER\",\n  \"phoneNumber\": \"+1111111111\",\n  \"organizationId\": \"{{bgv_org_id}}\",\n  \"permissions\": [\"ticket:view\", \"ticket:update\", \"ticket:comment\"],\n  \"accessibleOrganizations\": [\"{{org1_id}}\", \"{{org2_id}}\"]\n}",
          "options": {
            "raw": {
              "language": "json"
            }
          }
        },
        "url": {
          "raw": "http://localhost:8000/secure/addHelper",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8000",
          "path": ["secure", "addHelper"]
        }
      }
    },
    {
      "name": "3. Create IT Ticket",
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Authorization",
            "value": "Bearer {{user_token}}",
            "type": "text"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"subject\": \"Cannot login to system\",\n  \"description\": \"Getting 401 error\",\n  \"category\": \"IT_ISSUE\",\n  \"priority\": \"HIGH\"\n}",
          "options": {
            "raw": {
              "language": "json"
            }
          }
        },
        "url": {
          "raw": "http://localhost:8000/secure/ticket/create",
          "protocol": "http",
          "host": ["localhost"],
          "port": "8000",
          "path": ["secure", "ticket", "create"]
        }
      }
    }
  ]
}
```

---

## **Next Steps**

1. ✅ Complete setup (organizations, users)
2. ✅ Test ticket creation
3. ✅ Verify emails received
4. ✅ Test support staff access
5. ✅ Test ticket management
6. ✅ Test access control
7. ✅ Build frontend UI


---

# 🔥 **REASSIGNMENT TESTING - NEW FEATURES**

## **Enhanced Reassignment with Category-Role Validation**

### **STEP 9: Test Category-Based Reassignment**

#### **9.1 Login as SUPER_ADMIN**

```http
POST http://localhost:8000/auth/login
Content-Type: application/json

{
  "email": "admin@bgvapp.in",
  "password": "your_password"
}
```

**Save token:** `<SUPER_ADMIN_TOKEN>`

---

#### **9.2 Get Available Assignees for IT Ticket**

```http
GET http://localhost:8000/secure/ticket/TKT-20251130121344-9781/available-assignees
Authorization: Bearer <SUPER_ADMIN_TOKEN>
```

**Expected Response:**
```json
{
  "ticketId": "TKT-20251130121344-9781",
  "category": "IT Support",
  "targetTeam": "IT_TEAM",
  "allowedRoles": [
    "SUPER_ADMIN",
    "SUPER_SPOC", 
    "SUPER_ADMIN_HELPER",
    "IT_SUPPORT",
    "TECHNICAL_SUPPORT",
    "HELPER"
  ],
  "availableAssignees": [
    {
      "userId": "692be7a01151ca854f808280",
      "email": "it-support@bgvapp.in",
      "name": "IT Support Team",
      "role": "SUPER_ADMIN_HELPER",
      "organizationId": "692408fc28187fc1976b7499",
      "phoneNumber": "+1111111111",
      "accessibleOrganizations": ["692408fc28187fc1976b7499"]
    },
    {
      "userId": "692be7a01151ca854f808281",
      "email": "helper@acme.com",
      "name": "Acme Helper",
      "role": "HELPER",
      "organizationId": "692408fc28187fc1976b7499",
      "phoneNumber": "+5555555555",
      "accessibleOrganizations": []
    }
  ],
  "organizationId": "692408fc28187fc1976b7499",
  "organizationName": "Acme Corp"
}
```

**✅ Should show only users with:**
- Correct roles for IT_TEAM
- Access to the ticket's organization
- Active status

---

#### **9.3 Valid Reassignment - IT Ticket to IT Support**

```http
PUT http://localhost:8000/secure/ticket/TKT-20251130121344-9781/reassign
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "assignedToEmail": "it-support@bgvapp.in",
  "reason": "Assigning to dedicated IT support specialist"
}
```

**Expected Response:**
```json
{
  "message": "Ticket reassigned successfully"
}
```

**✅ Should succeed because:**
- IT_SUPPORT role is allowed for IT_ISSUE tickets
- User has access to the organization
- User is active

---

#### **9.4 Invalid Reassignment - IT Ticket to HR User**

```http
PUT http://localhost:8000/secure/ticket/TKT-20251130121344-9781/reassign
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "assignedToEmail": "hr@acme.com",
  "reason": "Testing invalid assignment"
}
```

**Expected Response:**
```json
{
  "detail": "User role 'ORG_HR' is not authorized to handle IT Support tickets. This ticket requires one of these roles: SUPER_ADMIN, SUPER_SPOC, SUPER_ADMIN_HELPER, IT_SUPPORT, TECHNICAL_SUPPORT, HELPER. Please assign to a user with appropriate role for IT_TEAM."
}
```

**❌ Should fail because:**
- ORG_HR role is NOT allowed for IT_TEAM tickets

---

#### **9.5 Invalid Reassignment - Different Organization**

**First create a user in different org:**
```http
POST http://localhost:8000/secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "userName": "TechCorp IT Support",
  "email": "it@techcorp.com",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+7777777777",
  "organizationId": "<techcorp_org_id>",
  "permissions": ["ticket:view", "ticket:update"],
  "accessibleOrganizations": ["<techcorp_org_id>"]
}
```

**Then try to assign Acme ticket to TechCorp user:**
```http
PUT http://localhost:8000/secure/ticket/TKT-20251130121344-9781/reassign
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "assignedToEmail": "it@techcorp.com",
  "reason": "Testing cross-org assignment"
}
```

**Expected Response:**
```json
{
  "detail": "User 'it@techcorp.com' belongs to a different organization and cannot be assigned this ticket."
}
```

**❌ Should fail because:**
- User belongs to TechCorp, ticket is from Acme Corp

---

### **STEP 10: Test Different Ticket Categories**

#### **10.1 Create Verification Ticket**

```http
POST http://localhost:8000/secure/ticket/create
Authorization: Bearer <ORG_HR_TOKEN>
Content-Type: application/json

{
  "subject": "Verification process stuck",
  "description": "Background verification for candidate has been pending for 5 days",
  "category": "VERIFICATION_ISSUE",
  "priority": "MEDIUM"
}
```

**Save ticketId from response**

---

#### **10.2 Get Available Assignees for Verification Ticket**

```http
GET http://localhost:8000/secure/ticket/<VERIFICATION_TICKET_ID>/available-assignees
Authorization: Bearer <SUPER_ADMIN_TOKEN>
```

**Expected Response:**
```json
{
  "category": "Verification Problem",
  "targetTeam": "VERIFICATION_TEAM",
  "allowedRoles": [
    "SUPER_ADMIN",
    "SUPER_SPOC",
    "SUPER_ADMIN_HELPER",
    "VERIFICATION_SPECIALIST",
    "ORG_HR",
    "HELPER"
  ],
  "availableAssignees": [
    {
      "email": "verification@bgvapp.in",
      "role": "SUPER_ADMIN_HELPER"
    },
    {
      "email": "hr@acme.com",
      "role": "ORG_HR"
    }
  ]
}
```

---

#### **10.3 Valid Assignment - Verification to ORG_HR**

```http
PUT http://localhost:8000/secure/ticket/<VERIFICATION_TICKET_ID>/reassign
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "assignedToEmail": "hr@acme.com",
  "reason": "ORG_HR can handle verification issues"
}
```

**✅ Should succeed because:**
- ORG_HR is allowed for VERIFICATION_TEAM
- Same organization

---

#### **10.4 Invalid Assignment - Verification to IT Support**

```http
PUT http://localhost:8000/secure/ticket/<VERIFICATION_TICKET_ID>/reassign
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "assignedToEmail": "it-support@bgvapp.in",
  "reason": "Testing invalid role assignment"
}
```

**❌ Should fail because:**
- IT_SUPPORT role not allowed for VERIFICATION_TEAM

---

### **STEP 11: Test SUPER_ADMIN_HELPER with Limited Org Access**

#### **11.1 Create Limited IT Support**

```http
POST http://localhost:8000/secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "userName": "Limited IT Support",
  "email": "it-limited@bgvapp.in",
  "password": "Welcome1",
  "role": "SUPER_ADMIN_HELPER",
  "phoneNumber": "+8888888888",
  "organizationId": "<bgv_org_id>",
  "permissions": ["ticket:view", "ticket:update"],
  "accessibleOrganizations": ["<techcorp_org_id>"]
}
```

**Note:** This user only has access to TechCorp, NOT Acme Corp

---

#### **11.2 Try to Assign Acme Ticket to Limited IT Support**

```http
PUT http://localhost:8000/secure/ticket/TKT-20251130121344-9781/reassign
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "assignedToEmail": "it-limited@bgvapp.in",
  "reason": "Testing org access validation"
}
```

**Expected Response:**
```json
{
  "detail": "User 'it-limited@bgvapp.in' does not have access to organization 'Acme Corp'. Please add this organization to their accessibleOrganizations."
}
```

**❌ Should fail because:**
- User doesn't have Acme Corp in accessibleOrganizations

---

#### **11.3 Check Available Assignees Excludes Limited User**

```http
GET http://localhost:8000/secure/ticket/TKT-20251130121344-9781/available-assignees
Authorization: Bearer <SUPER_ADMIN_TOKEN>
```

**✅ Should NOT include `it-limited@bgvapp.in` in the list**

---

### **STEP 12: Test All Category Combinations**

#### **12.1 Create Billing Ticket**

```http
POST http://localhost:8000/secure/ticket/create
Authorization: Bearer <ORG_HR_TOKEN>
Content-Type: application/json

{
  "subject": "Payment issue",
  "description": "Invoice payment failed",
  "category": "BILLING",
  "priority": "HIGH"
}
```

#### **12.2 Test Valid Billing Assignment to SPOC**

```http
PUT http://localhost:8000/secure/ticket/<BILLING_TICKET_ID>/reassign
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "assignedToEmail": "spoc@acme.com",
  "reason": "SPOC can handle billing issues"
}
```

**✅ Should succeed - SPOC allowed for FINANCE_TEAM**

#### **12.3 Test Invalid Billing Assignment to HELPER**

```http
PUT http://localhost:8000/secure/ticket/<BILLING_TICKET_ID>/reassign
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "assignedToEmail": "helper@acme.com",
  "reason": "Testing invalid assignment"
}
```

**❌ Should fail - HELPER not allowed for FINANCE_TEAM**

---

### **STEP 13: Test Bug Report Category**

#### **13.1 Create Bug Report Ticket**

```http
POST http://localhost:8000/secure/ticket/create
Authorization: Bearer <ORG_HR_TOKEN>
Content-Type: application/json

{
  "subject": "System bug found",
  "description": "Application crashes when uploading files",
  "category": "BUG_REPORT",
  "priority": "HIGH"
}
```

#### **13.2 Check Available Assignees for Bug Report**

```http
GET http://localhost:8000/secure/ticket/<BUG_TICKET_ID>/available-assignees
Authorization: Bearer <SUPER_ADMIN_TOKEN>
```

**Expected allowedRoles:**
```json
{
  "allowedRoles": [
    "SUPER_ADMIN",
    "SUPER_SPOC", 
    "SUPER_ADMIN_HELPER",
    "DEVELOPER",
    "TECHNICAL_LEAD",
    "SPOC"
  ]
}
```

#### **13.3 Test Valid Bug Assignment to SPOC**

```http
PUT http://localhost:8000/secure/ticket/<BUG_TICKET_ID>/reassign
Authorization: Bearer <SUPER_ADMIN_TOKEN>
Content-Type: application/json

{
  "assignedToEmail": "spoc@acme.com",
  "reason": "SPOC can handle development issues"
}
```

**✅ Should succeed**

---

## **Complete Reassignment Test Matrix**

| Ticket Category | Valid Roles | Invalid Roles | Test Status |
|----------------|-------------|---------------|-------------|
| **IT_ISSUE** | SUPER_ADMIN, SUPER_SPOC, SUPER_ADMIN_HELPER, IT_SUPPORT, TECHNICAL_SUPPORT, HELPER | ORG_HR, SPOC | ✅ |
| **VERIFICATION_ISSUE** | SUPER_ADMIN, SUPER_SPOC, SUPER_ADMIN_HELPER, VERIFICATION_SPECIALIST, ORG_HR, HELPER | IT_SUPPORT, SPOC | ✅ |
| **HR_QUERY** | SUPER_ADMIN, SUPER_SPOC, SUPER_ADMIN_HELPER, HR_SPECIALIST, ORG_HR, HELPER | IT_SUPPORT, SPOC | ✅ |
| **BILLING** | SUPER_ADMIN, SUPER_SPOC, SUPER_ADMIN_HELPER, FINANCE_SPECIALIST, SPOC, ORG_HR | HELPER, IT_SUPPORT | ✅ |
| **BUG_REPORT** | SUPER_ADMIN, SUPER_SPOC, SUPER_ADMIN_HELPER, DEVELOPER, TECHNICAL_LEAD, SPOC | ORG_HR, HELPER | ✅ |
| **FEATURE_REQUEST** | SUPER_ADMIN, SUPER_SPOC, SUPER_ADMIN_HELPER, PRODUCT_MANAGER, SPOC | ORG_HR, HELPER | ✅ |

---

## **Postman Collection for Reassignment Testing**

### **Environment Variables**
```json
{
  "admin_token": "eyJhbGc...",
  "acme_org_id": "692408fc28187fc1976b7499",
  "techcorp_org_id": "692408fc28187fc1976b7500",
  "it_ticket_id": "TKT-20251130121344-9781",
  "verification_ticket_id": "TKT-20251130121344-9782"
}
```

### **Test Sequence**

1. **Login as SUPER_ADMIN** → Get token
2. **Create test users** → IT Support, HR, Limited IT Support
3. **Create tickets** → IT, Verification, Billing, Bug Report
4. **Test valid assignments** → Correct role + org access
5. **Test invalid assignments** → Wrong role or no org access
6. **Check available assignees** → Verify filtering works

---

## **Expected Results Summary**

### **✅ Valid Assignments**
- IT ticket → IT_SUPPORT (same org)
- IT ticket → SUPER_ADMIN_HELPER (with org access)
- Verification ticket → ORG_HR (same org)
- Billing ticket → SPOC (same org)
- Bug ticket → SPOC (same org)

### **❌ Invalid Assignments**
- IT ticket → ORG_HR (wrong role)
- IT ticket → IT_SUPPORT (different org)
- Verification ticket → IT_SUPPORT (wrong role)
- Billing ticket → HELPER (wrong role)
- Any ticket → Inactive user

### **🔍 Available Assignees Filtering**
- Shows only users with correct roles
- Shows only users with org access
- Shows only active users
- Excludes users without proper permissions

---

## **Troubleshooting Reassignment Issues**

### **"User role not authorized" Error**
- Check ticket category vs user role mapping
- Verify role is in allowed list for that category
- Create user with correct role if needed

### **"No access to organization" Error**
- Check user's `organizationId` matches ticket org
- For SUPER_ADMIN_HELPER: check `accessibleOrganizations` array
- Add org to user's accessible list if needed

### **"User not found" Error**
- Verify email address is correct
- Check user exists and is active
- Check user has `isActive: true`

### **Empty Available Assignees List**
- No users have correct role + org access combination
- Create appropriate support staff for that org
- Add org access to existing support staff

---

## **Quick Validation Commands**

```bash
# Check user's role and org access
GET /secure/users/{userId}

# Check ticket details
GET /secure/ticket/{ticketId}

# Check available assignees
GET /secure/ticket/{ticketId}/available-assignees

# Test reassignment
PUT /secure/ticket/{ticketId}/reassign
{
  "assignedToEmail": "user@company.com",
  "reason": "Testing assignment"
}
```

This enhanced testing guide ensures the category-based role validation works correctly and prevents invalid ticket assignments while maintaining proper organization access control.