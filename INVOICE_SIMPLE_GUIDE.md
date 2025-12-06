# Invoice Generation - Simple Guide

## 📋 **Overview**

Generate invoices for completed verification checks. Prices are fetched from the organization's `services` array.

## 🚀 **Usage**

### **Generate Invoice**

```bash
POST /secure/generate_invoice
Content-Type: multipart/form-data

Parameters:
- verificationId: "verification_object_id"
```

**Example:**
```bash
curl -X POST "http://localhost:8000/secure/generate_invoice" \
  -H "Authorization: Bearer your-jwt-token" \
  -F "verificationId=674a1234567890abcdef1234"
```

## 📊 **Response**

```json
{
  "invoiceNumber": "INV-20240115-abc123",
  "invoiceDate": "2024-01-15T10:30:00Z",
  "invoiceId": "invoice_id",
  "verificationId": "verification_id",
  
  "organization": {
    "organizationId": "org_id",
    "organizationName": "hydra",
    "email": "hydra@gmail.com",
    "phone": "8331086719",
    "gstNumber": "29ABLDE1234F1Z6"
  },
  
  "candidate": {
    "candidateId": "candidate_id",
    "candidateName": "John Doe",
    "email": "john@example.com",
    "phone": "+91-9876543210"
  },
  
  "items": [
    {
      "checkName": "pan_aadhaar_seeding",
      "stage": "primary",
      "price": 20.0,
      "completedAt": "2024-01-15T09:00:00Z"
    },
    {
      "checkName": "education_check_manual",
      "stage": "secondary",
      "price": 20.0,
      "completedAt": "2024-01-15T10:00:00Z"
    },
    {
      "checkName": "credit_report",
      "stage": "primary",
      "price": 30.0,
      "completedAt": "2024-01-15T09:30:00Z"
    }
  ],
  "totalItems": 3,
  
  "subtotal": 70.0,
  "taxRate": 0.18,
  "tax": 12.6,
  "grandTotal": 82.6,
  "currency": "INR",
  
  "warnings": null
}
```

## 🔍 **How It Works**

1. **Get Verification** → Extract organizationId
2. **Get Organization** → Extract `services` array
3. **Build Pricing Map** → Convert services to `{ serviceName: price }` map
4. **Loop Through Checks** → Find all COMPLETED checks
5. **Calculate Price** → Get price from pricing map for each check
6. **Calculate Tax** → Add 18% GST
7. **Save Invoice** → Store in `invoices` collection
8. **Return Invoice** → Complete invoice details

## 💰 **Pricing Configuration**

Prices are stored in the organization's `services` array:

```json
{
  "_id": ObjectId("org_id"),
  "organizationName": "hydra",
  "services": [
    { "serviceName": "pan_aadhaar_seeding", "price": "20" },
    { "serviceName": "credit_report", "price": "30" },
    { "serviceName": "education_check_manual", "price": "20" },
    { "serviceName": "ai_cv_validation", "price": "75" }
  ]
}
```

## ✅ **What Gets Billed**

- ✅ **COMPLETED** checks → Included in invoice
- ❌ **PENDING** checks → Not billed
- ❌ **FAILED** checks → Not billed
- ❌ **NOT_STARTED** checks → Not billed

## ⚠️ **Important Notes**

1. **Only Completed Checks**: Only checks with status `COMPLETED` are billed
2. **Organization Pricing**: Each organization has its own pricing
3. **Missing Prices**: If a check doesn't have a price configured, it's skipped with a warning
4. **Tax**: 18% GST is automatically added
5. **Invoice Storage**: Invoices are saved to `invoices` collection

## 🔐 **Access Control**

### **Who Can Generate Invoices:**

1. **SUPER_ADMIN / SUPER_SPOC**
   - ✅ Can generate invoices for **any organization**
   - ✅ Full access to all verifications

2. **SPOC (BGV Staff)**
   - ✅ Can generate invoices for **any organization**
   - ✅ Must have email with `@bgv.local` or `bgvapp.in` domain

3. **SUPER_ADMIN_HELPER**
   - ✅ Can generate invoices for **accessible organizations only**
   - ✅ Access controlled by `accessibleOrganizations` array

4. **ORG_HR / ORG_SPOC**
   - ✅ Can generate invoices for **their own organization only**
   - ✅ Must match `organizationId`

5. **HELPER**
   - ✅ Can generate invoices for:
     - Candidates they created (`createdBy` matches their email)
     - Verifications they initiated (`initiatedBy` matches their email)
   - ✅ Must belong to the same organization
   - ❌ Cannot access other candidates/verifications in their org

## 📝 **Example Scenario**

**Organization**: hydra
**Verification**: 5 checks total
- ✅ pan_aadhaar_seeding (COMPLETED) → ₹20
- ✅ credit_report (COMPLETED) → ₹30
- ✅ education_check_manual (COMPLETED) → ₹20
- ⏳ ai_cv_validation (PENDING) → Not billed
- ❌ court_record (FAILED) → Not billed

**Invoice Calculation:**
- Subtotal: ₹70 (20 + 30 + 20)
- Tax (18%): ₹12.60
- **Grand Total: ₹82.60**

## 🔒 **Access Control Examples**

### **Example 1: SUPER_ADMIN**
```
User: admin@bgv.local (SUPER_ADMIN)
Verification: Any organization
Result: ✅ Allowed - Can generate invoice
```

### **Example 2: SUPER_ADMIN_HELPER**
```
User: helper@company.com (SUPER_ADMIN_HELPER)
Accessible Orgs: [org1, org2, org3]
Verification: org2
Result: ✅ Allowed - org2 is in accessible list

Verification: org5
Result: ❌ Denied - org5 not in accessible list
```

### **Example 3: ORG_HR**
```
User: hr@hydra.com (ORG_HR, organizationId: hydra_id)
Verification: hydra_id
Result: ✅ Allowed - Same organization

Verification: other_org_id
Result: ❌ Denied - Different organization
```

### **Example 4: HELPER**
```
User: helper@hydra.com (HELPER, organizationId: hydra_id)
Candidate: Created by helper@hydra.com
Result: ✅ Allowed - Helper created this candidate

Verification: Initiated by helper@hydra.com
Result: ✅ Allowed - Helper initiated this verification

Candidate: Created by other@hydra.com
Verification: Initiated by other@hydra.com
Result: ❌ Denied - Helper didn't create or initiate
```

---

## 🚨 **Error Handling**

### **"Organization services/pricing not configured"**
- **Cause**: Organization doesn't have `services` array
- **Solution**: Add services with prices to organization document

### **"Prices not configured for checks: [check_name]"**
- **Cause**: Completed check doesn't have price in organization's services
- **Solution**: Add the check to organization's services array
- **Note**: Check is skipped, invoice still generated for other checks

### **"Verification not found"**
- **Cause**: Invalid verificationId
- **Solution**: Check the verificationId is correct

## 💡 **Tips**

1. **Configure All Services**: Make sure all check types your organization uses have prices configured
2. **Review Before Billing**: Check the invoice items before sending to client
3. **Track Invoices**: Use the returned `invoiceId` to track payment status
4. **Update Prices**: Update organization's services array to change prices

---

Simple, clean, and works with your organization schema! 🎯
