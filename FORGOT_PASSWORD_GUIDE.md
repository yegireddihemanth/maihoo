# Forgot Password System - Simple Guide

## 📋 **Overview**

Simple 2-step password reset system with email verification.

## 🔄 **Workflow**

```
1. User clicks "Forgot Password"
   ↓
2. Enters email → Receives reset link with token
   ↓
3. Clicks link → Opens reset form
   ↓
4. Enters: email, phone, new password, confirm password
   ↓
5. System validates → Password updated
```

## 🚀 **API Endpoints**

### **1. Request Password Reset**

```bash
POST /public/forgot-password
Content-Type: multipart/form-data

Parameters:
- email: user@example.com
```

**Response:**
```json
{
  "message": "If the email exists, a password reset link has been sent"
}
```

**What Happens:**
- Generates unique reset token
- Token valid for 1 hour
- Sends email with reset link
- Link format: `https://your-app.com/reset-password?token=abc123`

---

### **2. Reset Password**

```bash
POST /public/reset-password
Content-Type: multipart/form-data

Parameters:
- token: abc123-reset-token (from email link)
- email: user@example.com
- organizationId: 69316eb36794dff9baa6e911
- new_password: NewPassword123
- confirm_password: NewPassword123
```

**Response:**
```json
{
  "message": "Password reset successful. You can now login with your new password.",
  "email": "user@example.com"
}
```

**Validation:**
- ✅ Token must be valid and not expired
- ✅ Email must match user's email
- ✅ Organization ID must match user's organization
- ✅ New password and confirm password must match
- ✅ Password must be at least 6 characters

---

## 📧 **Email Template**

Users receive this email:

```
Subject: Password Reset Request

Hello [User Name],

You requested to reset your password. Click the link below to reset:

[Reset Password Button/Link]

This link will expire in 1 hour.

If you didn't request this, please ignore this email.

Best regards,
BGV Team
```

---

## 🔒 **Security Features**

1. **Token Expiry**: Reset tokens expire after 1 hour
2. **Email Verification**: Must provide correct email
3. **Organization Verification**: Must provide correct organization ID
4. **No Email Enumeration**: Same response whether email exists or not
5. **One-Time Token**: Token deleted after successful reset
6. **Activity Logging**: All password resets are logged

---

## 💡 **Usage Examples**

### **Example 1: Request Reset**

```bash
curl -X POST "http://localhost:8000/public/forgot-password" \
  -F "email=shanwik.iyer@inorbit.io"
```

**User receives email with link:**
```
https://your-app.com/reset-password?token=550e8400-e29b-41d4-a716-446655440000
```

### **Example 2: Reset Password**

```bash
curl -X POST "http://localhost:8000/public/reset-password" \
  -F "token=550e8400-e29b-41d4-a716-446655440000" \
  -F "email=shanwik.iyer@inorbit.io" \
  -F "organizationId=69316eb36794dff9baa6e911" \
  -F "new_password=NewSecurePass123" \
  -F "confirm_password=NewSecurePass123"
```

**Success Response:**
```json
{
  "message": "Password reset successful. You can now login with your new password.",
  "email": "shanwik.iyer@inorbit.io"
}
```

---

## 🚨 **Error Handling**

### **"Passwords do not match"**
- **Cause**: `new_password` ≠ `confirm_password`
- **Solution**: Ensure both passwords are identical

### **"Password must be at least 6 characters"**
- **Cause**: Password too short
- **Solution**: Use password with 6+ characters

### **"Invalid or expired reset token"**
- **Cause**: Token expired (>1 hour) or invalid
- **Solution**: Request new reset link

### **"Email does not match"**
- **Cause**: Email doesn't match the user's registered email
- **Solution**: Use the correct email address

### **"Organization ID does not match"**
- **Cause**: Organization ID doesn't match the user's organization
- **Solution**: Use the correct organization ID

---

## 🔧 **Frontend Integration**

### **Step 1: Forgot Password Page**

```html
<form action="/public/forgot-password" method="POST">
  <input type="email" name="email" placeholder="Enter your email" required>
  <button type="submit">Send Reset Link</button>
</form>
```

### **Step 2: Reset Password Page**

```html
<!-- URL: /reset-password?token=abc123 -->
<form action="/public/reset-password" method="POST">
  <input type="hidden" name="token" value="abc123">
  <input type="email" name="email" placeholder="Email" required>
  <input type="text" name="organizationId" placeholder="Organization ID" required>
  <input type="password" name="new_password" placeholder="New Password" required>
  <input type="password" name="confirm_password" placeholder="Confirm Password" required>
  <button type="submit">Reset Password</button>
</form>
```

---

## 📊 **Database Changes**

When user requests reset, these fields are added to user document:

```json
{
  "_id": ObjectId("user_id"),
  "email": "user@example.com",
  "password": "old_password",
  "resetToken": "550e8400-e29b-41d4-a716-446655440000",
  "resetTokenExpiry": "2024-01-15T11:30:00Z"
}
```

After successful reset:

```json
{
  "_id": ObjectId("user_id"),
  "email": "user@example.com",
  "password": "new_password",
  "updatedAt": "2024-01-15T10:45:00Z"
  // resetToken and resetTokenExpiry removed
}
```

---

## ⚠️ **Important Notes**

1. **Public Endpoints**: Both endpoints are public (no authentication required)
2. **Token Expiry**: Reset links expire after 1 hour
3. **Security**: Email + Phone verification required
4. **Password Hashing**: In production, hash passwords before storing!
5. **Email Service**: Requires email service configured (uses `send_email` from `email_utils`)

---

## 🔐 **Production Recommendations**

1. **Hash Passwords**: Use bcrypt or similar to hash passwords
2. **Rate Limiting**: Limit reset requests per email (prevent abuse)
3. **HTTPS Only**: Use HTTPS for reset links
4. **Custom Domain**: Update reset link URL to your domain
5. **Email Service**: Configure proper email service (SendGrid, AWS SES, etc.)

---

Simple, secure, and user-friendly password reset! 🎯
