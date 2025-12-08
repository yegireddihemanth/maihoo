# 📊 Batch Invoice Generation Guide

## **Overview**

Generate consolidated invoices for all verifications of an organization in one go.

**Permissions:** SUPER_ADMIN and SUPER_SPOC only

---

## **Endpoints**

### **1. Generate Batch Invoice**

```
POST /secure/generate_batch_invoice
```

**Request Body:**
```json
{
  "organizationId": "507f1f77bcf86cd799439011",
  "includeCompleted": true,      // Include fully completed verifications
  "includePartial": false,        // Include verifications with some completed checks
  "startDate": "2024-01-01T00:00:00Z",  // Optional
  "endDate": "2024-12-31T23:59:59Z"     // Optional
}
```

**Response:**
```json
{
  "invoiceType": "BATCH",
  "invoiceNumber": "BATCH-INV-20241207-abc123",
  "invoiceDate": "2024-12-07T08:30:00Z",
  
  "organization": {
    "organizationId": "507f1f77bcf86cd799439011",
    "organizationName": "Tata Consultancy Services",
    "email": "billing@tcs.com",
    "phone": "+91-9876543210",
    "gstNumber": "29ABCDE1234F1Z5",
    "address": "Mumbai, India"
  },
  
  "billingPeriod": {
    "startDate": "2024-01-01T00:00:00Z",
    "endDate": "2024-12-31T23:59:59Z"
  },
  
  "summary": {
    "totalVerifications": 25,
    "totalCompletedChecks": 150,
    "includeCompleted": true,
    "includePartial": false
  },
  
  "verifications": [
    {
      "verificationId": "507f1f77bcf86cd799439012",
      "candidateName": "John Doe",
      "candidateEmail": "john@example.com",
      "overallStatus": "COMPLETED",
      "completedChecks": 6,
      "verificationTotal": 720.0,
      "createdAt": "2024-11-15T10:00:00Z"
    },
    // ... more verifications
  ],
  
  "items": [
    {
      "checkName": "Employment Verification",
      "stage": "employment",
      "price": 120.0,
      "completedAt": "2024-11-15T12:00:00Z"
    },
    // ... all completed checks from all verifications
  ],
  
  "totalItems": 150,
  "subtotal": 18000.0,
  "taxRate": 0.18,
  "tax": 3240.0,
  "grandTotal": 21240.0,
  "currency": "INR",
  
  "warnings": ["Criminal Record Check"],  // Checks without pricing
  
  "generatedBy": "admin@bgvapp.in",
  "generatedAt": "2024-12-07T08:30:00Z",
  "invoiceId": "507f1f77bcf86cd799439099"
}
```

---

### **2. Get Batch Invoices**

```
GET /secure/get_batch_invoices?organizationId=507f1f77bcf86cd799439011
```

**Response:**
```json
{
  "invoices": [
    {
      "_id": "507f1f77bcf86cd799439099",
      "invoiceNumber": "BATCH-INV-20241207-abc123",
      "organization": {...},
      "grandTotal": 21240.0,
      "createdAt": "2024-12-07T08:30:00Z"
    }
  ],
  "total": 1
}
```

---

## **Usage Examples**

### **Example 1: Monthly Invoice for Organization**

```bash
curl -X POST https://maihootech.in/secure/generate_batch_invoice \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "organizationId": "507f1f77bcf86cd799439011",
    "includeCompleted": true,
    "includePartial": false,
    "startDate": "2024-11-01T00:00:00Z",
    "endDate": "2024-11-30T23:59:59Z"
  }'
```

### **Example 2: All Completed Verifications (No Date Filter)**

```bash
curl -X POST https://maihootech.in/secure/generate_batch_invoice \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "organizationId": "507f1f77bcf86cd799439011",
    "includeCompleted": true,
    "includePartial": false
  }'
```

### **Example 3: Include Partial Verifications**

```bash
curl -X POST https://maihootech.in/secure/generate_batch_invoice \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "organizationId": "507f1f77bcf86cd799439011",
    "includeCompleted": true,
    "includePartial": true
  }'
```

---

## **Toggle Options Explained**

### **includeCompleted: true**
- Includes verifications where `overallStatus = "COMPLETED"`
- All checks in these verifications are done
- Recommended for final billing

### **includePartial: true**
- Includes verifications with some completed checks (but not fully completed)
- Useful for interim billing
- Bills only the completed checks, not pending ones

### **Both true**
- Includes ALL verifications with any completed checks
- Maximum billing coverage

### **Both false**
- No verifications will be included
- Will return error

---

## **Features**

✅ **Aggregates Multiple Verifications**
- Combines all verifications for an organization
- Single consolidated invoice

✅ **Detailed Breakdown**
- Per-verification summary
- Itemized list of all completed checks
- Candidate details for each verification

✅ **Date Range Filtering**
- Generate monthly/quarterly invoices
- Custom date ranges

✅ **Automatic Pricing**
- Fetches prices from organization's service configuration
- Warns about missing prices

✅ **Tax Calculation**
- 18% GST automatically calculated
- Shows subtotal, tax, and grand total

✅ **Audit Trail**
- Saves to database
- Logs activity
- Tracks who generated the invoice

---

## **Permission Matrix**

| Role | Generate Batch Invoice | View Batch Invoices |
|------|----------------------|-------------------|
| SUPER_ADMIN | ✅ Yes | ✅ Yes |
| SUPER_SPOC | ✅ Yes | ✅ Yes |
| SPOC | ❌ No | ❌ No |
| ORG_HR | ❌ No | ❌ No |
| HELPER | ❌ No | ❌ No |

---

## **Database Schema**

Batch invoices are saved in the `invoices` collection:

```json
{
  "_id": ObjectId("..."),
  "invoiceType": "BATCH",
  "invoiceNumber": "BATCH-INV-20241207-abc123",
  "organization": {...},
  "verifications": [...],
  "items": [...],
  "grandTotal": 21240.0,
  "createdAt": "2024-12-07T08:30:00Z",
  "createdBy": "admin@bgvapp.in"
}
```

---

## **Comparison: Single vs Batch Invoice**

| Feature | Single Invoice | Batch Invoice |
|---------|---------------|---------------|
| **Scope** | One verification | Multiple verifications |
| **Permissions** | All roles (with access) | SUPER_ADMIN/SUPER_SPOC only |
| **Use Case** | Per-candidate billing | Monthly/quarterly billing |
| **Date Filter** | No | Yes |
| **Verification Summary** | No | Yes |
| **Endpoint** | `/secure/generate_invoice` | `/secure/generate_batch_invoice` |

---

## **Common Use Cases**

### **1. Monthly Billing**
Generate invoice for all verifications completed in November:
```json
{
  "organizationId": "...",
  "includeCompleted": true,
  "includePartial": false,
  "startDate": "2024-11-01T00:00:00Z",
  "endDate": "2024-11-30T23:59:59Z"
}
```

### **2. Quarterly Billing**
Generate invoice for Q4 2024:
```json
{
  "organizationId": "...",
  "includeCompleted": true,
  "includePartial": false,
  "startDate": "2024-10-01T00:00:00Z",
  "endDate": "2024-12-31T23:59:59Z"
}
```

### **3. All Pending Billing**
Generate invoice for all completed verifications (no date limit):
```json
{
  "organizationId": "...",
  "includeCompleted": true,
  "includePartial": false
}
```

---

## **Error Handling**

### **403 Forbidden**
```json
{
  "detail": "Only SUPER_ADMIN and SUPER_SPOC can generate batch invoices"
}
```
**Solution:** Only SUPER_ADMIN and SUPER_SPOC can use this endpoint.

### **404 Not Found - Organization**
```json
{
  "detail": "Organization not found"
}
```
**Solution:** Check the organizationId is correct.

### **404 Not Found - No Verifications**
```json
{
  "detail": "No verifications found matching the criteria"
}
```
**Solution:** 
- Check date range
- Verify organization has verifications
- Check toggle settings

### **404 Not Found - No Completed Checks**
```json
{
  "detail": "No completed checks found for billing"
}
```
**Solution:** Organization has verifications but no completed checks.

### **400 Bad Request - No Pricing**
```json
{
  "detail": "Organization services/pricing not configured"
}
```
**Solution:** Configure pricing in organization's services array.

---

## **Testing**

### **Postman Collection**

**1. Generate Batch Invoice**
```
POST {{baseUrl}}/secure/generate_batch_invoice
Authorization: Bearer {{token}}
Content-Type: application/json

Body:
{
  "organizationId": "{{orgId}}",
  "includeCompleted": true,
  "includePartial": false,
  "startDate": "2024-11-01T00:00:00Z",
  "endDate": "2024-11-30T23:59:59Z"
}
```

**2. Get Batch Invoices**
```
GET {{baseUrl}}/secure/get_batch_invoices?organizationId={{orgId}}
Authorization: Bearer {{token}}
```

---

## **Frontend Integration**

```javascript
// Generate batch invoice
const generateBatchInvoice = async (orgId, startDate, endDate) => {
  const response = await fetch('/secure/generate_batch_invoice', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      organizationId: orgId,
      includeCompleted: true,
      includePartial: false,
      startDate: startDate,
      endDate: endDate
    })
  });
  
  const invoice = await response.json();
  
  // Display invoice
  console.log(`Invoice: ${invoice.invoiceNumber}`);
  console.log(`Total: ₹${invoice.grandTotal}`);
  console.log(`Verifications: ${invoice.summary.totalVerifications}`);
  
  return invoice;
};

// Get all batch invoices
const getBatchInvoices = async (orgId) => {
  const response = await fetch(
    `/secure/get_batch_invoices?organizationId=${orgId}`,
    {
      headers: { 'Authorization': `Bearer ${token}` }
    }
  );
  
  const data = await response.json();
  return data.invoices;
};
```

---

## **Summary**

✅ **Created:** Batch invoice generation endpoint  
✅ **Permissions:** SUPER_ADMIN and SUPER_SPOC only  
✅ **Features:** Date filtering, completion toggles, detailed breakdown  
✅ **Database:** Saves to invoices collection with type "BATCH"  
✅ **Audit:** Full activity logging  

**Ready to use! 🎉**
