# 🌐 Subdomain Setup Guide for Maihoo BGV

Complete guide to set up organization-specific subdomains like `tcs.maihootech.in`, `infosys.maihootech.in`, etc.

---

## 📋 **Overview**

Each organization gets their own subdomain:
- **TCS**: `tcs.maihootech.in`
- **Infosys**: `infosys.maihootech.in`
- **Wipro**: `wipro.maihootech.in`

---

## 🔧 **Step 1: DNS Configuration**

### **Option A: Wildcard DNS (Recommended)**

Go to your DNS provider (GoDaddy, Namecheap, Cloudflare, etc.) and add:

```
Type: A Record
Host: *
Points to: Your EC2 IP (e.g., 13.232.xxx.xxx)
TTL: 3600
```

✅ **This allows ALL subdomains** (tcs, infosys, wipro, etc.) to work automatically.

### **Option B: Individual Subdomains**

If wildcard is not available, add each subdomain manually:

```
Type: A Record
Host: tcs
Points to: Your EC2 IP
TTL: 3600
```

Repeat for each organization.

### **Verification**

Wait 5-10 minutes, then test:
```bash
ping tcs.maihootech.in
# Should resolve to your EC2 IP
```

---

## 🖥️ **Step 2: Nginx Configuration (on EC2)**

SSH into your EC2 and update Nginx config:

```bash
sudo nano /etc/nginx/sites-available/maihoo
```

Update the config:

```nginx
server {
    listen 80;
    server_name maihootech.in *.maihootech.in;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
```

**Key line**: `server_name maihootech.in *.maihootech.in;`

Test and reload:
```bash
sudo nginx -t
sudo systemctl reload nginx
```

---

## 🔐 **Step 3: SSL Certificate (HTTPS)**

Get SSL for wildcard domain:

```bash
sudo certbot --nginx -d maihootech.in -d *.maihootech.in
```

If wildcard doesn't work, add each subdomain:
```bash
sudo certbot --nginx -d maihootech.in -d tcs.maihootech.in -d infosys.maihootech.in
```

---

## 💻 **Step 4: FastAPI Implementation (Already Done!)**

The middleware has been added to `main.py`:

```python
@app.middleware("http")
async def extract_subdomain(request: Request, call_next):
    """Extracts subdomain from request"""
    host = request.headers.get("host", "")
    parts = host.split(".")
    
    if len(parts) >= 3 and parts[-2] == "maihootech" and parts[-1] == "in":
        request.state.subdomain = parts[0]
        request.state.organization_domain = parts[0]
    else:
        request.state.subdomain = None
        request.state.organization_domain = None
    
    response = await call_next(request)
    return response
```

---

## 📝 **Step 5: Using Subdomains in Your Endpoints**

### **Example 1: Get Current Subdomain**

```python
@app.get("/api/current-org")
async def get_current_org(request: Request):
    subdomain = get_subdomain(request)
    
    if not subdomain:
        raise HTTPException(400, "No organization subdomain detected")
    
    # Find organization by subdomain
    org = await organizationsCol.find_one({"subdomain": subdomain})
    
    if not org:
        raise HTTPException(404, f"Organization '{subdomain}' not found")
    
    return {"organization": subdomain, "data": org}
```

### **Example 2: Restrict Access by Subdomain**

```python
@app.get("/api/candidates")
async def get_candidates(request: Request, user: dict = Depends(requireAuth)):
    subdomain = get_subdomain(request)
    
    # Only show candidates for this organization
    candidates = await candidatesCol.find({
        "organizationDomain": subdomain
    }).to_list(100)
    
    return {"candidates": candidates}
```

### **Example 3: Organization-Specific Login**

```python
@app.post("/api/login")
async def login(request: Request, body: LoginRequest):
    subdomain = get_subdomain(request)
    
    # Find user in this organization only
    user = await usersCol.find_one({
        "email": body.email,
        "organizationDomain": subdomain
    })
    
    if not user:
        raise HTTPException(401, "Invalid credentials for this organization")
    
    # ... rest of login logic
```

---

## 🏢 **Step 6: Register Organizations with Subdomains**

### **Database Schema**

Your organizations collection should have:

```json
{
  "_id": ObjectId("..."),
  "organizationName": "Tata Consultancy Services",
  "subdomain": "tcs",
  "mainDomain": "tcs.com",
  "spocName": "John Doe",
  "spocEmail": "john@tcs.com",
  "services": [...],
  "credentials": {...},
  "createdAt": "2024-01-01T00:00:00Z"
}
```

### **Registration Endpoint**

```python
class OrganizationRegister(BaseModel):
    organizationName: str
    subdomain: str  # e.g., "tcs"
    spocName: str
    spocEmail: str
    mainDomain: Optional[str] = None
    services: List[dict] = []

@app.post("/api/admin/register-organization")
async def register_organization(body: OrganizationRegister):
    # Check if subdomain already exists
    existing = await organizationsCol.find_one({"subdomain": body.subdomain})
    if existing:
        raise HTTPException(400, f"Subdomain '{body.subdomain}' already taken")
    
    # Validate subdomain format (alphanumeric, lowercase)
    if not body.subdomain.isalnum() or not body.subdomain.islower():
        raise HTTPException(400, "Subdomain must be lowercase alphanumeric")
    
    # Generate default password
    default_password = str(uuid.uuid4())[:8]
    
    # Create organization
    org_data = {
        "organizationName": body.organizationName,
        "subdomain": body.subdomain,
        "mainDomain": body.mainDomain,
        "spocName": body.spocName,
        "spocEmail": body.spocEmail,
        "services": body.services,
        "credentials": {
            "totalAllowed": 10,
            "used": 0
        },
        "createdAt": datetime.now(timezone.utc).isoformat()
    }
    
    result = await organizationsCol.insert_one(org_data)
    
    # Send welcome email
    send_organization_welcome_email(
        toEmail=body.spocEmail,
        organizationName=body.organizationName,
        spocName=body.spocName,
        loginEmail=body.spocEmail,
        defaultPassword=default_password,
        mainDomain=body.mainDomain,
        subDomain=f"{body.subdomain}.maihootech.in",
        services=body.services,
        credentials=org_data["credentials"]
    )
    
    return {
        "message": "Organization registered successfully",
        "subdomain": f"{body.subdomain}.maihootech.in",
        "organizationId": str(result.inserted_id)
    }
```

---

## 🧪 **Testing**

### **Test 1: DNS Resolution**
```bash
ping tcs.maihootech.in
# Should resolve to your EC2 IP
```

### **Test 2: Subdomain Detection**
```bash
curl -H "Host: tcs.maihootech.in" http://your-ec2-ip/api/current-org
```

### **Test 3: Browser**
Visit: `http://tcs.maihootech.in/docs`

---

## 🎯 **Quick Registration Example**

### **Using Postman/cURL**

```bash
curl -X POST https://maihootech.in/api/admin/register-organization \
  -H "Content-Type: application/json" \
  -d '{
    "organizationName": "Tata Consultancy Services",
    "subdomain": "tcs",
    "spocName": "Rajesh Kumar",
    "spocEmail": "rajesh@tcs.com",
    "mainDomain": "tcs.com",
    "services": [
      {"serviceName": "Employment Verification", "price": 120.0},
      {"serviceName": "Education Verification", "price": 150.0}
    ]
  }'
```

### **Response**
```json
{
  "message": "Organization registered successfully",
  "subdomain": "tcs.maihootech.in",
  "organizationId": "507f1f77bcf86cd799439011"
}
```

---

## ✅ **Checklist**

- [ ] DNS wildcard A record added
- [ ] Nginx configured for `*.maihootech.in`
- [ ] SSL certificate obtained
- [ ] FastAPI middleware added (✅ Done!)
- [ ] Helper function `get_subdomain()` available (✅ Done!)
- [ ] Organization registration endpoint created
- [ ] Test subdomain resolution
- [ ] Test API with subdomain

---

## 🚨 **Common Issues**

### **Issue 1: Subdomain not resolving**
- Wait 10-15 minutes for DNS propagation
- Check DNS with: `nslookup tcs.maihootech.in`

### **Issue 2: SSL certificate error**
- Wildcard SSL requires DNS validation
- Use individual certificates if wildcard fails

### **Issue 3: Subdomain returns None**
- Check Nginx `proxy_set_header Host $host;`
- Verify middleware is registered before routes

---

## 📞 **Support**

If you need help:
1. Check DNS propagation: https://dnschecker.org
2. Test Nginx config: `sudo nginx -t`
3. Check FastAPI logs: `journalctl -u maihoo -f`

---

**Your subdomain system is ready! 🎉**
