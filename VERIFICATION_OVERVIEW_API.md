# Verification Overview API

## 🎯 **Overview**

The Verification Overview endpoint provides role-based access to verification data with strict permissions based on user roles and organizational boundaries.

## 📋 **Endpoint**

```http
GET /secure/verification/overview?organizationId={orgId}&status={status}&limit={limit}
Authorization: Bearer <token>
```

## 🔐 **Role-Based Access Control**

### **SUPER_SPOC** 👑
- ✅ **Full Access**: Can view ALL verifications from all roles and organizations
- ✅ **Cross-Organization**: No organizational restrictions
- ✅ **All Roles**: Can see verifications initiated by any role

### **SUPER_ADMIN** 🔧
- ✅ **Limited Access**: Can view verifications from SUPER_ADMIN_HELPER and himself
- ✅ **Cross-Organization**: Can filter by any organization
- ❌ **Role Restriction**: Cannot see ORG_HR, SPOC, or HELPER verifications

### **SPOC (Organization SPOC)** 🏢
- ✅ **Organization Level**: Can view verifications in his organization only
- ✅ **Multi-Role**: Can see verifications by himself, ORG_HR, and HELPER
- ❌ **Organization Boundary**: Cannot see other organizations

### **ORG_HR** 👥
- ✅ **Organization Level**: Can view verifications in his organization only
- ✅ **Limited Roles**: Can see his own verifications and HELPER verifications
- ❌ **Role Restriction**: Cannot see SPOC verifications

### **SUPER_ADMIN_HELPER** 🛠️
- ✅ **Accessible Organizations**: Can view verifications in assigned organizations
- ✅ **Own Work**: Can see verifications initiated by or assigned to him
- ❌ **Limited Scope**: Only accessible organizations

### **HELPER** 🚫
- ❌ **No Access**: Returns empty result with message
- ❌ **Security**: Helpers cannot view verification overview

---

## 📊 **Query Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `organizationId` | string | No | Filter by specific organization ID |
| `status` | string | No | Filter by verification status (PENDING, IN_PROGRESS, COMPLETED, FAILED) |
| `limit` | integer | No | Limit number of results (default: 100, max: 1000) |

---

## 📋 **Response Schema**

### **Success Response (200):**
```json
{
  "total": 150,
  "returned": 25,
  "verifications": [
    {
      "verificationId": "507f1f77bcf86cd799439011",
      "candidateId": "507f1f77bcf86cd799439012",
      "candidateName": "John Doe",
      "candidateEmail": "john.doe@example.com",
      "organizationId": "507f1f77bcf86cd799439013",
      "organizationName": "Acme Corp",
      "overallStatus": "IN_PROGRESS",
      "currentStage": "primary",
      "initiatedBy": "hr@acme.com",
      "initiatedByRole": "ORG_HR",
      "assignedTo": "verifier@bgvapp.in",
      "initiatedAt": "2025-11-30T06:43:44.168521+00:00",
      "updatedAt": "2025-11-30T08:15:00.000Z",
      "completionPercentage": 75.0,
      "totalChecks": 4,
      "completedChecks": 3,
      "slaStatus": "ON_TIME",
      "priority": "HIGH"
    }
  ],
  "statusSummary": {
    "PENDING": 45,
    "IN_PROGRESS": 32,
    "COMPLETED": 68,
    "FAILED": 5
  },
  "filters": {
    "userRole": "ORG_HR",
    "organizationId": "507f1f77bcf86cd799439013",
    "status": "IN_PROGRESS",
    "limit": 100
  },
  "permissions": {
    "canViewAll": false,
    "canViewCrossOrg": false,
    "organizationRestricted": true,
    "accessibleOrganizations": []
  }
}
```

### **HELPER Response (200):**
```json
{
  "total": 0,
  "verifications": [],
  "message": "Helpers do not have access to verification overview",
  "userRole": "HELPER"
}
```

### **No Access Response (200):**
```json
{
  "total": 0,
  "verifications": [],
  "message": "No accessible organizations",
  "userRole": "SUPER_ADMIN_HELPER"
}
```

---

## 🧪 **Testing Examples**

### **Test 1: SUPER_SPOC (Full Access)**
```bash
curl -X GET "http://localhost:8000/secure/verification/overview" \
  -H "Authorization: Bearer <SUPER_SPOC_TOKEN>"
```
**Expected**: All verifications from all organizations and roles

### **Test 2: SUPER_ADMIN (Limited Access)**
```bash
curl -X GET "http://localhost:8000/secure/verification/overview?organizationId=507f1f77bcf86cd799439013" \
  -H "Authorization: Bearer <SUPER_ADMIN_TOKEN>"
```
**Expected**: Only SUPER_ADMIN_HELPER verifications + own verifications

### **Test 3: ORG_HR (Organization Restricted)**
```bash
curl -X GET "http://localhost:8000/secure/verification/overview?status=IN_PROGRESS" \
  -H "Authorization: Bearer <ORG_HR_TOKEN>"
```
**Expected**: Only own + HELPER verifications from same organization

### **Test 4: HELPER (No Access)**
```bash
curl -X GET "http://localhost:8000/secure/verification/overview" \
  -H "Authorization: Bearer <HELPER_TOKEN>"
```
**Expected**: Empty result with "no access" message

---

## 📊 **Role Access Matrix**

| User Role | Own Verifications | HELPER | ORG_HR | SPOC | SUPER_ADMIN_HELPER | SUPER_ADMIN | SUPER_SPOC |
|-----------|-------------------|--------|--------|------|-------------------|-------------|------------|
| **SUPER_SPOC** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SUPER_ADMIN** | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| **SPOC** | ✅ | ✅* | ✅* | ✅ | ❌ | ❌ | ❌ |
| **ORG_HR** | ✅ | ✅* | ✅ | ❌ | ❌ | ❌ | ❌ |
| **SUPER_ADMIN_HELPER** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **HELPER** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

**\* Only within same organization**

---

## 🔍 **Filtering Examples**

### **Filter by Organization (SUPER_SPOC)**
```bash
GET /secure/verification/overview?organizationId=507f1f77bcf86cd799439013
```

### **Filter by Status (ORG_HR)**
```bash
GET /secure/verification/overview?status=COMPLETED
```

### **Combined Filters (SUPER_ADMIN)**
```bash
GET /secure/verification/overview?organizationId=507f1f77bcf86cd799439013&status=IN_PROGRESS&limit=50
```

---

## 📈 **Response Fields Explanation**

### **Verification Object:**
- `verificationId`: Unique verification identifier
- `candidateName`: Constructed from firstName + lastName
- `overallStatus`: Current verification status
- `initiatedByRole`: Role of person who started verification
- `completionPercentage`: Calculated from completed/total checks
- `slaStatus`: SLA compliance status (future enhancement)

### **Status Summary:**
- Aggregated count of verifications by status
- Useful for dashboard widgets
- Respects same role-based filtering

### **Permissions Object:**
- `canViewAll`: User can see all verifications
- `canViewCrossOrg`: User can see multiple organizations
- `organizationRestricted`: User limited to own organization
- `accessibleOrganizations`: List of accessible org IDs

---

## 🚨 **Error Responses**

### **401 Unauthorized:**
```json
{
  "detail": "Not authenticated"
}
```

### **403 Forbidden:**
```json
{
  "detail": "Role 'UNKNOWN_ROLE' not authorized for verification overview"
}
```

### **400 Bad Request:**
```json
{
  "detail": "Invalid organization ID format"
}
```

---

## 💡 **Implementation Notes**

### **Performance Considerations:**
- Query uses indexes on `organizationId`, `initiatedBy`, `overallStatus`
- Limit parameter prevents large result sets
- Aggregation pipeline for status summary is efficient

### **Security Features:**
- Strict role-based access control
- Organization boundary enforcement
- No data leakage between roles
- Audit trail through role tracking

### **Future Enhancements:**
- SLA status calculation based on timestamps
- Priority-based filtering
- Date range filtering
- Export functionality for authorized roles

This endpoint provides a comprehensive, secure overview of verifications while maintaining strict role-based access control! 🎉