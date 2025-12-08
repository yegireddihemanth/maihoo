# 🔐 Subdomain Login Flow - Frontend Guide

## **Overview**

Users log in at the main domain (`maihootech.in`), then get redirected to their organization's subdomain (`tcs.maihootech.in`).

---

## **Flow Diagram**

```
┌─────────────────────────────────────────────────────────────┐
│ 1. User visits: https://maihootech.in                       │
│    Shows: Generic login page                                │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. User enters credentials:                                 │
│    Email: john@tcs.com                                      │
│    Password: ********                                       │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. POST /auth/login                                         │
│    Response includes: organizationSubdomain = "tcs"         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Frontend redirects to:                                   │
│    https://tcs.maihootech.in/dashboard                      │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. All subsequent requests go to:                           │
│    https://tcs.maihootech.in/api/*                          │
└─────────────────────────────────────────────────────────────┘
```

---

## **Backend Changes (✅ Done!)**

Login response now includes `organizationSubdomain`:

```json
{
  "userName": "John Doe",
  "email": "john@tcs.com",
  "role": "SPOC",
  "organizationId": "507f1f77bcf86cd799439011",
  "organizationName": "Tata Consultancy Services",
  "organizationSubdomain": "tcs",  // ✅ NEW FIELD
  "token": "eyJhbGc...",
  "session": "created",
  "permissions": [...],
  "services": [...]
}
```

---

## **Frontend Implementation**

### **1. Login Component (React/Next.js Example)**

```javascript
// LoginPage.jsx
import { useState } from 'react';
import { useRouter } from 'next/router';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const router = useRouter();

  const handleLogin = async (e) => {
    e.preventDefault();
    
    try {
      const response = await fetch('https://maihootech.in/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include', // Important for cookies
        body: JSON.stringify({ email, password })
      });

      if (!response.ok) {
        throw new Error('Invalid credentials');
      }

      const data = await response.json();
      
      // Store user data in localStorage/sessionStorage
      localStorage.setItem('user', JSON.stringify(data));
      localStorage.setItem('token', data.token);
      
      // ✅ Redirect to organization subdomain
      if (data.organizationSubdomain) {
        window.location.href = `https://${data.organizationSubdomain}.maihootech.in/dashboard`;
      } else {
        // Fallback for users without subdomain (super admin?)
        router.push('/dashboard');
      }
      
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <form onSubmit={handleLogin}>
      <input 
        type="email" 
        value={email} 
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Email"
      />
      <input 
        type="password" 
        value={password} 
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
      />
      <button type="submit">Login</button>
      {error && <p className="error">{error}</p>}
    </form>
  );
}
```

---

### **2. API Client Configuration**

```javascript
// api/client.js
const getBaseURL = () => {
  const hostname = window.location.hostname;
  
  // If already on subdomain, use current domain
  if (hostname.includes('.maihootech.in')) {
    return `https://${hostname}`;
  }
  
  // Otherwise use main domain
  return 'https://maihootech.in';
};

export const apiClient = {
  baseURL: getBaseURL(),
  
  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const response = await fetch(url, {
      ...options,
      credentials: 'include', // Always include cookies
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    });
    
    if (!response.ok) {
      throw new Error(`API Error: ${response.statusText}`);
    }
    
    return response.json();
  }
};

// Usage:
// await apiClient.request('/secure/getCandidates');
```

---

### **3. Protected Route Component**

```javascript
// components/ProtectedRoute.jsx
import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';

export default function ProtectedRoute({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const response = await fetch('/auth/session', {
          credentials: 'include'
        });
        
        if (response.ok) {
          setIsAuthenticated(true);
        } else {
          // Redirect to main login page
          window.location.href = 'https://maihootech.in/login';
        }
      } catch (err) {
        window.location.href = 'https://maihootech.in/login';
      }
    };

    checkAuth();
  }, []);

  if (!isAuthenticated) {
    return <div>Loading...</div>;
  }

  return children;
}
```

---

### **4. Logout Handler**

```javascript
// utils/auth.js
export const logout = async () => {
  try {
    await fetch('/auth/logout', {
      method: 'POST',
      credentials: 'include'
    });
  } catch (err) {
    console.error('Logout error:', err);
  } finally {
    // Clear local storage
    localStorage.removeItem('user');
    localStorage.removeItem('token');
    
    // Redirect to main login page
    window.location.href = 'https://maihootech.in/login';
  }
};
```

---

## **Cookie Configuration**

### **Important: Cookie Domain Settings**

For cookies to work across subdomains, your backend should set:

```python
# Current setting (✅ Already correct in your code)
response.set_cookie(
    key="session",
    value=token,
    domain=None,  # ✅ Let browser handle it automatically
    # OR
    domain=".maihootech.in",  # ✅ Works for all subdomains
    httponly=True,
    secure=True,  # Required for HTTPS
    samesite="Lax"
)
```

**Your current code already has `domain=None`**, which is perfect! The browser will automatically handle subdomain cookies.

---

## **Frontend Deployment Options**

### **Option 1: Single Deployment (Recommended)**

Deploy your frontend once at `maihootech.in`, and it will work for all subdomains:

```nginx
# Nginx config
server {
    server_name maihootech.in *.maihootech.in;
    
    location / {
        # Serve frontend static files
        root /var/www/frontend/build;
        try_files $uri /index.html;
    }
    
    location /api/ {
        # Proxy API requests to backend
        proxy_pass http://127.0.0.1:8000;
    }
}
```

### **Option 2: Separate Frontend/Backend Domains**

- Frontend: `app.maihootech.in` (and `*.app.maihootech.in`)
- Backend: `api.maihootech.in`

Update CORS in backend:
```python
origins = [
    "https://app.maihootech.in",
    "https://*.app.maihootech.in",
    # ...
]
```

---

## **Testing Checklist**

### **1. Test Login Flow**
```bash
# Login at main domain
curl -X POST https://maihootech.in/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "john@tcs.com", "password": "pass123"}'

# Should return: organizationSubdomain = "tcs"
```

### **2. Test Subdomain Access**
```bash
# Access API from subdomain
curl https://tcs.maihootech.in/auth/session \
  -H "Cookie: session=YOUR_TOKEN"

# Should return user session
```

### **3. Test Cookie Sharing**
- Login at `maihootech.in`
- Navigate to `tcs.maihootech.in`
- Cookie should still be valid ✅

---

## **Common Issues & Solutions**

### **Issue 1: Cookie not working on subdomain**
**Solution:** Set `domain=".maihootech.in"` in cookie config

### **Issue 2: CORS error on subdomain**
**Solution:** Add subdomain to CORS origins:
```python
origins = ["https://maihootech.in", "https://*.maihootech.in"]
```

### **Issue 3: Redirect loop**
**Solution:** Check that `/auth/session` endpoint works on subdomain

### **Issue 4: organizationSubdomain is null**
**Solution:** Make sure organization has `subdomain` field in database:
```javascript
db.organizations.updateOne(
  { _id: ObjectId("...") },
  { $set: { subdomain: "tcs" } }
)
```

---

## **Database Schema**

Make sure your organizations collection has the `subdomain` field:

```json
{
  "_id": ObjectId("507f1f77bcf86cd799439011"),
  "organizationName": "Tata Consultancy Services",
  "subdomain": "tcs",  // ✅ Required for redirect
  "spocEmail": "spoc@tcs.com",
  "services": [...],
  "createdAt": "2024-01-01T00:00:00Z"
}
```

---

## **Summary**

✅ **Backend:** Returns `organizationSubdomain` in login response  
✅ **Frontend:** Redirects to `{subdomain}.maihootech.in` after login  
✅ **Cookies:** Work across all subdomains automatically  
✅ **APIs:** All routes work at subdomain URLs  

**Your setup is ready! Just implement the frontend redirect logic.** 🚀
