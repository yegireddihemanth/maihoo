# Manual Ticket Assignment Workflow

## **Overview**

Tickets are now created **UNASSIGNED** by default. ORG_HR manually assigns them to available IT support staff.

---

## **New Workflow**

```
1. ORG_HR creates ticket
   ↓
2. Ticket created as UNASSIGNED (except CRITICAL)
   ↓
3. ORG_HR views available IT support for their org
   ↓
4. ORG_HR assigns ticket to chosen IT support
   ↓
5. IT support receives email notification
   ↓
6. IT support works on ticket
   ↓
7. If busy, IT support can reassign to another team member
```

---

## **Step-by-Step Guide**

### **Step 1: ORG_HR Creates Ticket**

```http
POST http://localhost:5001/secure/ticket/create
Authorization: Bearer <ORG_HR_TOKEN>

{
  "subject": "Cannot login to system",
  "description": "User getting 401 error",
  "category": "IT_ISSUE",
  "priority": "HIGH"
}
```

**Response:**
```json
{
  "message": "Ticket created successfully - awaiting assignment",
  "ticketId": "TKT-20251130-1234",
  "assignedTo": "Unassigned - Please assign to support staff",
  "slaDeadline": "2025-11-30T15:00:00Z"
}
```

✅ **No email sent yet** (ticket is unassigned)

---

### **Step 2: ORG_HR Views Available IT Support**

```http
GET http://localhost:5001/secure/getUsers
Authorization: Bearer <ORG_HR_TOKEN>
```

**Filter for IT support with access to your org:**
```json
{
  "users": [
    {
      "email": "hemanthdevapple@gmail.com",
      "userName": "Hemanth Dev IT Support",
      "role": "SUPER_ADMIN_HELPER",
      "accessibleOrganizations": ["68ffb000..."]  // ✅ Has your org
    },
    {
      "email": "hemanthyegireddyad@gmail.com",
      "userName": "Hemanth IT Support",
      "role": "SUPER_ADMIN_HELPER",
      "accessibleOrganizations": ["68ffb000..."]  // ✅ Has your org
    }
  ]
}
```

---

### **Step 3: ORG_HR Assigns Ticket**

```http
PUT http://localhost:5001/secure/ticket/TKT-20251130-1234/reassign
Authorization: Bearer <ORG_HR_TOKEN>

{
  "assignedToEmail": "hemanthdevapple@gmail.com",
  "reason": "Assigning to Hemanth Dev - available now"
}
```

**Response:**
```json
{
  "message": "Ticket reassigned successfully"
}
```

✅ **Email sent to hemanthdevapple@gmail.com**

---

### **Step 4: IT Support Receives Email**

```
Subject: Ticket TKT-20251130-1234 Assigned to You

Hi Hemanth Dev IT Support,

A ticket has been reassigned to you:

Ticket ID: TKT-20251130-1234
Subject: Cannot login to system
Category: IT_ISSUE
Priority: HIGH
Reassigned By: ORG_HR

Reason: Assigning to Hemanth Dev - available now

Please review and respond.
```

---

### **Step 5: IT Support Works on Ticket**

```http
# Login as IT support
POST http://localhost:5001/auth/login
{
  "email": "hemanthdevapple@gmail.com",
  "password": "Welcome1"
}

# View assigned tickets
GET http://localhost:5001/secure/ticket/list?assignedToMe=true

# Start working
PUT http://localhost:5001/secure/ticket/TKT-20251130-1234/status
{
  "status": "IN_PROGRESS",
  "comment": "Working on it"
}
```

---

### **Step 6: IT Support Reassigns (If Busy)**

```http
PUT http://localhost:5001/secure/ticket/TKT-20251130-1234/reassign
Authorization: Bearer <IT_SUPPORT_TOKEN>

{
  "assignedToEmail": "hemanthyegireddyad@gmail.com",
  "reason": "I'm busy with another critical issue. Reassigning to Hemanth."
}
```

✅ **IT support can now reassign** (new feature!)

---

## **Exception: CRITICAL Priority**

CRITICAL tickets are **auto-assigned to SUPER_SPOC** (immediate escalation):

```http
POST http://localhost:5001/secure/ticket/create

{
  "subject": "URGENT: System down",
  "category": "IT_ISSUE",
  "priority": "CRITICAL"  // ← Auto-assigns to SUPER_SPOC
}
```

**Response:**
```json
{
  "message": "Ticket created successfully and assigned to Super SPOC",
  "assignedTo": "Super SPOC",
  "ticketId": "TKT-xxx"
}
```

---

## **Who Can Assign/Reassign Tickets?**

| Role | Can Assign? | Can Reassign? |
|------|-------------|---------------|
| **SUPER_ADMIN** | ✅ | ✅ |
| **SUPER_SPOC** | ✅ | ✅ |
| **SPOC** | ✅ (own org) | ✅ (own org) |
| **ORG_HR** | ✅ (own org) | ✅ (own org) |
| **Assigned IT Support** | ❌ | ✅ **NEW!** |
| **Other IT Support** | ❌ | ❌ |
| **HELPER** | ❌ | ❌ |

---

## **Email Notifications**

### **Before (Old System)**
```
Ticket created
  ↓
Email sent to:
  - hemanthdevapple@gmail.com ✉️
  - hemanthyegireddyad@gmail.com ✉️
  - All IT team members ✉️
```
❌ Everyone gets spammed

### **After (New System)**
```
Ticket created (unassigned)
  ↓
No email sent ✅

ORG_HR assigns to hemanthdevapple@gmail.com
  ↓
Email sent to:
  - hemanthdevapple@gmail.com ✉️ ONLY
```
✅ Only assigned person gets email

---

## **Benefits**

### **1. No Email Spam**
- ✅ Only assigned person receives email
- ✅ Other IT team members not disturbed

### **2. Manual Control**
- ✅ ORG_HR decides who to assign based on availability
- ✅ No random assignment
- ✅ Better workload distribution

### **3. Flexibility**
- ✅ Assigned person can reassign if busy
- ✅ No need to contact admin to reassign

### **4. Accountability**
- ✅ Clear ownership (one person assigned)
- ✅ No confusion about who's responsible

---

## **Complete Example**

### **Scenario: 3 IT Support Members for Same Org**

**Setup:**
```javascript
// IT Support 1
{
  email: "it1@bgvapp.in",
  accessibleOrganizations: ["org_maihoo"]
}

// IT Support 2
{
  email: "it2@bgvapp.in",
  accessibleOrganizations: ["org_maihoo"]
}

// IT Support 3
{
  email: "it3@bgvapp.in",
  accessibleOrganizations: ["org_maihoo"]
}
```

---

**Workflow:**

1. **ORG_HR creates ticket**
   - Ticket created as UNASSIGNED
   - No emails sent

2. **ORG_HR checks availability**
   - IT1: Busy with 5 tickets
   - IT2: Available (2 tickets)
   - IT3: On leave

3. **ORG_HR assigns to IT2**
   ```http
   PUT /secure/ticket/TKT-xxx/reassign
   {
     "assignedToEmail": "it2@bgvapp.in",
     "reason": "IT2 is available"
   }
   ```
   - Email sent to IT2 only ✉️

4. **IT2 starts working**
   - Updates status to IN_PROGRESS

5. **IT2 gets urgent issue**
   - Reassigns to IT1:
   ```http
   PUT /secure/ticket/TKT-xxx/reassign
   {
     "assignedToEmail": "it1@bgvapp.in",
     "reason": "Got urgent issue, reassigning"
   }
   ```
   - Email sent to IT1 ✉️

6. **IT1 completes ticket**
   - Resolves and closes

---

## **Migration Notes**

### **Old Behavior**
- ✅ Auto-assigned randomly
- ✅ Email to entire team
- ❌ No control over assignment
- ❌ Email spam

### **New Behavior**
- ✅ Manual assignment by ORG_HR
- ✅ Email to assigned person only
- ✅ Assigned person can reassign
- ✅ CRITICAL still auto-escalates

---

## **Testing**

### **Test 1: Create Unassigned Ticket**

```bash
POST /secure/ticket/create
{
  "category": "IT_ISSUE",
  "priority": "HIGH"
}

# Expected:
# - assignedTo: "Unassigned"
# - No email sent
```

---

### **Test 2: ORG_HR Assigns Ticket**

```bash
PUT /secure/ticket/TKT-xxx/reassign
{
  "assignedToEmail": "it@bgvapp.in",
  "reason": "Assigning"
}

# Expected:
# - Ticket assigned
# - Email sent to it@bgvapp.in ONLY
```

---

### **Test 3: IT Support Reassigns**

```bash
# Login as IT support
POST /auth/login
{ "email": "it@bgvapp.in" }

# Reassign
PUT /secure/ticket/TKT-xxx/reassign
{
  "assignedToEmail": "it2@bgvapp.in",
  "reason": "I'm busy"
}

# Expected:
# - Success (IT support can reassign)
# - Email sent to it2@bgvapp.in
```

---

### **Test 4: CRITICAL Auto-Assigns**

```bash
POST /secure/ticket/create
{
  "category": "IT_ISSUE",
  "priority": "CRITICAL"
}

# Expected:
# - Auto-assigned to SUPER_SPOC
# - Email sent to SUPER_SPOC
```

---

## **Summary**

✅ **Tickets created unassigned** (except CRITICAL)  
✅ **ORG_HR manually assigns** to available IT support  
✅ **Only assigned person gets email** (no spam)  
✅ **Assigned person can reassign** if busy  
✅ **CRITICAL tickets auto-escalate** to SUPER_SPOC  

