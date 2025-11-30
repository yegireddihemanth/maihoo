# Ticket Assignment Logic - How It Works

## **Overview**

When a ticket is created, the system automatically assigns it to the appropriate support staff based on:
1. ✅ **Category** (IT, Verification, HR, etc.)
2. ✅ **Organization Access** (support staff must have access to the org)
3. ✅ **Priority** (CRITICAL tickets escalate to SUPER_SPOC)
4. ✅ **Load Balancing** (random selection among available staff)

---

## **Assignment Flow**

```
User creates ticket
    ↓
Check category (IT_ISSUE, VERIFICATION_ISSUE, etc.)
    ↓
Find support staff with:
  - Correct role/permissions
  - Access to this organization ✅ NEW
  - Active status
    ↓
If found → Assign randomly (load balancing)
If not found → Fallback to SUPER_ADMIN
If still not found → Error with helpful message ✅ NEW
```

---

## **Category-Based Assignment**

### **IT_ISSUE**

**Priority 1:** Dedicated IT Support (SUPER_ADMIN_HELPER)
```javascript
// Looks for users with:
{
  "role": "SUPER_ADMIN_HELPER",
  "permissions": ["ticket:update"],
  "accessibleOrganizations": ["<ticket_org_id>"],  // ✅ Must have org access
  "isActive": true
}
```

**Priority 2:** Fallback to SUPER_ADMIN/SUPER_SPOC
```javascript
{
  "role": {"$in": ["SUPER_ADMIN", "SUPER_SPOC"]},
  "isActive": true
}
```

**Priority 3:** No one available
```
❌ Error: "No IT Support staff available for organization 'Acme Corp'. 
Please contact your administrator to assign support staff to this organization."
```

---

### **VERIFICATION_ISSUE**

**Priority 1:** Dedicated Verification Support
```javascript
{
  "role": "SUPER_ADMIN_HELPER",
  "permissions": ["verification:view"],
  "accessibleOrganizations": ["<ticket_org_id>"],  // ✅ Must have org access
  "isActive": true
}
```

**Priority 2:** Fallback to SUPER_ADMIN/SUPER_SPOC

**Priority 3:** No one available → Error

---

### **CRITICAL Priority (Any Category)**

**Always escalates to SUPER_SPOC** regardless of category:
```javascript
{
  "role": "SUPER_SPOC",
  "isActive": true
}
```

---

## **Organization Access Check**

### **Before (Broken)**
```python
# Found IT support users without checking org access
itSupport = await usersCol.find({
    "role": "SUPER_ADMIN_HELPER",
    "permissions": {"$in": ["ticket:update"]},
    "isActive": True
})
# ❌ Might assign to IT support who can't access this org
```

### **After (Fixed)**
```python
# Only find IT support with access to this org
itSupport = await usersCol.find({
    "role": "SUPER_ADMIN_HELPER",
    "permissions": {"$in": ["ticket:update"]},
    "accessibleOrganizations": userOrgId,  # ✅ Must have org access
    "isActive": True
})
# ✅ Only assigns to IT support who can see the ticket
```

---

## **Example Scenarios**

### **Scenario 1: IT Ticket in Maihoo Org**

**Setup:**
- Organization: Maihoo (`68ffb000e4b2a7e23ccf1e50`)
- IT Support 1: `hemanthyegireddyad@gmail.com`
  - `accessibleOrganizations: ["6924c2f2d12643803cbd41cf"]` ❌ No Maihoo access
- IT Support 2: `hemanthdevapple@gmail.com`
  - `accessibleOrganizations: ["68ffb000e4b2a7e23ccf1e50"]` ✅ Has Maihoo access

**Result:**
- ✅ Ticket assigned to `hemanthdevapple@gmail.com` (has org access)
- ❌ NOT assigned to `hemanthyegireddyad@gmail.com` (no org access)

---

### **Scenario 2: No IT Support for Org**

**Setup:**
- Organization: TechCorp (`org_techcorp_id`)
- IT Support 1: Has access to Acme, Paytm (not TechCorp)
- IT Support 2: Has access to XYZ Corp (not TechCorp)

**Result:**
```
❌ Error 503: "No IT Support staff available for organization 'TechCorp'. 
Please contact your administrator to assign support staff to this organization."
```

**Fix:** Add TechCorp to an IT support user's `accessibleOrganizations`

---

### **Scenario 3: Critical Ticket (Auto-escalation)**

**Setup:**
- Any organization
- Priority: CRITICAL

**Result:**
- ✅ Always assigned to SUPER_SPOC (bypasses org access check)
- ✅ SUPER_SPOC has access to all orgs

---

## **Viewing Tickets**

### **SUPER_ADMIN_HELPER Can See Tickets If:**

1. **Ticket is from accessible organization**
   ```javascript
   ticket.organizationId in user.accessibleOrganizations
   ```

2. **OR ticket is assigned to them** ✅ NEW
   ```javascript
   ticket.assignedToEmail === user.email
   ```

This allows IT support to see tickets assigned to them even from orgs they don't normally have access to.

---

## **Error Messages**

### **No IT Support Available**
```
503 Service Unavailable
"No IT Support staff available for organization 'Acme Corp'. 
Please contact your administrator to assign support staff to this organization."
```

**Solution:** Add the organization to an IT support user's `accessibleOrganizations`

---

### **No Verification Support Available**
```
503 Service Unavailable
"No Verification Problem staff available for organization 'Acme Corp'. 
Please contact your administrator to assign support staff to this organization."
```

**Solution:** Add the organization to a verification support user's `accessibleOrganizations`

---

## **How to Fix "No Support Staff" Error**

### **Option 1: Add Org to Existing IT Support**

```http
PUT http://localhost:5001/secure/updateUser/<IT_SUPPORT_USER_ID>
Authorization: Bearer <SUPER_ADMIN_TOKEN>

{
  "accessibleOrganizations": [
    "existing_org_1",
    "existing_org_2",
    "68ffb000e4b2a7e23ccf1e50"  // ← Add the new org
  ]
}
```

---

### **Option 2: Create New IT Support for This Org**

```http
POST http://localhost:5001/secure/addHelper
Authorization: Bearer <SUPER_ADMIN_TOKEN>

{
  "userName": "IT Support for Maihoo",
  "email": "it-maihoo@bgvapp.in",
  "role": "SUPER_ADMIN_HELPER",
  "organizationId": "BGV_ORG_ID",
  "permissions": ["ticket:view", "ticket:update", "ticket:comment"],
  "accessibleOrganizations": ["68ffb000e4b2a7e23ccf1e50"]
}
```

---

## **Best Practices**

### **1. Assign IT Support to All Active Orgs**

When creating IT support users, include all organizations they should support:

```javascript
{
  "accessibleOrganizations": [
    "org_acme",
    "org_techcorp",
    "org_xyz",
    "org_maihoo"
  ]
}
```

---

### **2. Use Multiple IT Support Users**

For load balancing, create multiple IT support users:

```javascript
// IT Support 1
{
  "email": "it-support-1@bgvapp.in",
  "accessibleOrganizations": ["org_acme", "org_techcorp"]
}

// IT Support 2
{
  "email": "it-support-2@bgvapp.in",
  "accessibleOrganizations": ["org_xyz", "org_maihoo"]
}
```

System will randomly pick one with access to the ticket's org.

---

### **3. SUPER_ADMIN as Fallback**

Always have at least one SUPER_ADMIN or SUPER_SPOC active:
- They have access to ALL organizations
- Act as fallback when no dedicated support available
- Handle CRITICAL priority tickets

---

## **Testing**

### **Test 1: Verify Org Access Check**

```bash
# 1. Create IT support with access to Org A only
POST /secure/addHelper
{
  "email": "it@bgvapp.in",
  "accessibleOrganizations": ["org_a"]
}

# 2. Create ticket in Org B
POST /secure/ticket/create
{
  "category": "IT_ISSUE",
  "organizationId": "org_b"
}

# Expected: Error "No IT Support staff available for organization 'Org B'"
```

---

### **Test 2: Verify Assignment to Correct IT Support**

```bash
# 1. Create two IT support users
# IT Support 1: Access to Org A
# IT Support 2: Access to Org B

# 2. Create ticket in Org A
POST /secure/ticket/create
{
  "category": "IT_ISSUE",
  "organizationId": "org_a"
}

# Expected: Assigned to IT Support 1 (has Org A access)
# NOT assigned to IT Support 2 (no Org A access)
```

---

### **Test 3: Verify IT Support Can See Assigned Tickets**

```bash
# 1. Create ticket in Org A, assigned to IT Support 1
# 2. Login as IT Support 1
# 3. View tickets

GET /secure/ticket/list

# Expected: See the ticket (even if Org A not in accessibleOrganizations)
# Because ticket is assigned to them
```

---

## **Summary**

✅ **Fixed:** IT support only assigned to tickets from orgs they have access to  
✅ **Fixed:** IT support can see tickets assigned to them (even from other orgs)  
✅ **Fixed:** Clear error message when no support staff available  
✅ **Improved:** Load balancing among available support staff  
✅ **Maintained:** CRITICAL tickets always escalate to SUPER_SPOC  


---

## **🔥 NEW: Category-Based Role Validation**

### **Enhanced Reassignment Logic**

When SUPER_ADMIN/SUPER_SPOC reassigns tickets, the system now validates:

1. ✅ **Organization Access** (existing)
2. ✅ **Category-Role Mapping** (NEW)
3. ✅ **User Active Status** (existing)

---

### **Category-Role Mapping**

Each ticket category requires specific roles:

#### **IT_ISSUE → IT_TEAM**
**Allowed Roles:**
- `SUPER_ADMIN` (full access)
- `SUPER_SPOC` (full access)
- `SUPER_ADMIN_HELPER` (with org access)
- `IT_SUPPORT` (specialized role)
- `TECHNICAL_SUPPORT` (specialized role)
- `HELPER` (basic support)

#### **VERIFICATION_ISSUE → VERIFICATION_TEAM**
**Allowed Roles:**
- `SUPER_ADMIN`, `SUPER_SPOC`
- `SUPER_ADMIN_HELPER` (with org access)
- `VERIFICATION_SPECIALIST` (specialized role)
- `ORG_HR` (organization level)
- `HELPER` (basic support)

#### **HR_QUERY → HR_TEAM**
**Allowed Roles:**
- `SUPER_ADMIN`, `SUPER_SPOC`
- `SUPER_ADMIN_HELPER` (with org access)
- `HR_SPECIALIST` (specialized role)
- `ORG_HR` (organization level)
- `HELPER` (basic support)

#### **BILLING → FINANCE_TEAM**
**Allowed Roles:**
- `SUPER_ADMIN`, `SUPER_SPOC`
- `SUPER_ADMIN_HELPER` (with org access)
- `FINANCE_SPECIALIST` (specialized role)
- `SPOC` (organization admin)
- `ORG_HR` (organization level)

#### **BUG_REPORT → DEV_TEAM**
**Allowed Roles:**
- `SUPER_ADMIN`, `SUPER_SPOC`
- `SUPER_ADMIN_HELPER` (with org access)
- `DEVELOPER` (specialized role)
- `TECHNICAL_LEAD` (specialized role)
- `SPOC` (organization admin)

#### **FEATURE_REQUEST → PRODUCT_TEAM**
**Allowed Roles:**
- `SUPER_ADMIN`, `SUPER_SPOC`
- `SUPER_ADMIN_HELPER` (with org access)
- `PRODUCT_MANAGER` (specialized role)
- `SPOC` (organization admin)

---

### **Reassignment Validation Flow**

```
SUPER_ADMIN wants to reassign IT ticket to user
    ↓
1. Check Organization Access
   ✅ User has access to ticket's org?
    ↓
2. Check Category-Role Validation (NEW)
   ✅ User role allowed for IT_ISSUE tickets?
    ↓
3. Check User Status
   ✅ User is active?
    ↓
If all pass → Reassign ticket
If any fail → Show specific error message
```

---

### **New Endpoints**

#### **PUT /secure/ticket/{ticketId}/reassign**
**Enhanced with category validation**

**Error Examples:**
```json
{
  "detail": "User role 'ORG_HR' is not authorized to handle IT Support tickets. This ticket requires one of these roles: SUPER_ADMIN, SUPER_SPOC, SUPER_ADMIN_HELPER, IT_SUPPORT, TECHNICAL_SUPPORT, HELPER. Please assign to a user with appropriate role for IT_TEAM."
}
```

#### **GET /secure/ticket/{ticketId}/available-assignees**
**NEW: Get filtered list of eligible assignees**

**Response:**
```json
{
  "ticketId": "TKT-20251130121344-9781",
  "category": "IT Support",
  "targetTeam": "IT_TEAM",
  "allowedRoles": ["SUPER_ADMIN", "SUPER_SPOC", "SUPER_ADMIN_HELPER", "IT_SUPPORT", "TECHNICAL_SUPPORT", "HELPER"],
  "availableAssignees": [
    {
      "userId": "692be7a01151ca854f808280",
      "email": "it-support@company.com",
      "name": "John Doe",
      "role": "SUPER_ADMIN_HELPER",
      "organizationId": "692408fc28187fc1976b7499",
      "accessibleOrganizations": ["692408fc28187fc1976b7499"]
    }
  ]
}
```

---

### **Example Scenarios**

#### **Scenario 1: Valid IT Assignment**
```
Ticket: IT_ISSUE in TVA org
Assignee: john@company.com (SUPER_ADMIN_HELPER)
Organization Access: ✅ Has TVA in accessibleOrganizations
Role Validation: ✅ SUPER_ADMIN_HELPER allowed for IT_TEAM
Result: ✅ Assignment successful
```

#### **Scenario 2: Invalid Role for Category**
```
Ticket: IT_ISSUE in TVA org
Assignee: hr@company.com (ORG_HR)
Organization Access: ✅ Belongs to TVA org
Role Validation: ❌ ORG_HR not allowed for IT_TEAM
Result: ❌ Error - "User role 'ORG_HR' is not authorized to handle IT Support tickets"
```

#### **Scenario 3: No Organization Access**
```
Ticket: BILLING in TVA org
Assignee: finance@other-company.com (FINANCE_SPECIALIST)
Organization Access: ❌ Belongs to different org
Role Validation: ✅ FINANCE_SPECIALIST allowed for FINANCE_TEAM
Result: ❌ Error - "User belongs to a different organization"
```

---

### **UI Integration**

#### **Smart Assignee Dropdown**
```javascript
// Frontend can call this to populate dropdown
GET /secure/ticket/TKT-123/available-assignees

// Shows only users who:
// 1. Have org access
// 2. Have correct role for category
// 3. Are active
```

#### **Category-Aware Assignment**
```javascript
// When category changes, refresh available assignees
onCategoryChange(newCategory) {
  fetchAvailableAssignees(ticketId);
  // Dropdown automatically filters to relevant roles
}
```

---

### **Benefits**

1. ✅ **Prevents Invalid Assignments**: Can't assign IT tickets to HR specialists
2. ✅ **Smart UI**: Dropdown shows only valid options
3. ✅ **Clear Error Messages**: Explains why assignment failed
4. ✅ **Maintains Security**: Organization boundaries still enforced
5. ✅ **Flexible Roles**: SUPER_ADMIN_HELPER can handle any category with org access

---

### **Testing Category Validation**

```bash
# Test 1: Try to assign IT ticket to HR user
PUT /secure/ticket/TKT-123/reassign
{
  "assignedToEmail": "hr@company.com"  // ORG_HR role
}
# Expected: Error about role not authorized for IT tickets

# Test 2: Get available assignees for IT ticket
GET /secure/ticket/TKT-123/available-assignees
# Expected: Only users with IT-compatible roles

# Test 3: Assign to valid IT support
PUT /secure/ticket/TKT-123/reassign
{
  "assignedToEmail": "it-support@company.com"  // SUPER_ADMIN_HELPER role
}
# Expected: Success
```