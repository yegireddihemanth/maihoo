#!/usr/bin/env python3
"""
Quick script to add AI CV Validation service to an organization
"""

import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB", "bgv_core")

async def add_ai_cv_service(org_id: str, price: float = 50.0):
    """Add AI CV Validation service to organization"""
    
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[MONGO_DB]
    orgsCol = db["organizations"]
    
    try:
        org_object_id = ObjectId(org_id)
    except:
        print(f"❌ Invalid organization ID: {org_id}")
        return
    
    # Check if organization exists
    org = await orgsCol.find_one({"_id": org_object_id})
    if not org:
        print(f"❌ Organization not found: {org_id}")
        return
    
    print(f"📋 Organization: {org.get('organizationName')}")
    
    # Check if AI CV Validation already exists
    services = org.get("services", [])
    existing = [s for s in services if s.get("serviceName") == "AI CV Validation"]
    
    if existing:
        print(f"⚠️  AI CV Validation already exists with price: ₹{existing[0].get('price')}")
        update = input("Update price? (y/n): ").lower()
        if update == 'y':
            # Update existing service
            for service in services:
                if service.get("serviceName") == "AI CV Validation":
                    service["price"] = price
            
            await orgsCol.update_one(
                {"_id": org_object_id},
                {"$set": {"services": services}}
            )
            print(f"✅ Updated AI CV Validation price to ₹{price}")
        else:
            print("❌ Cancelled")
    else:
        # Add new service
        new_service = {
            "serviceName": "AI CV Validation",
            "price": price
        }
        
        await orgsCol.update_one(
            {"_id": org_object_id},
            {"$push": {"services": new_service}}
        )
        print(f"✅ Added AI CV Validation service with price: ₹{price}")
    
    # Show all services
    updated_org = await orgsCol.find_one({"_id": org_object_id})
    print("\n📊 All Services:")
    for service in updated_org.get("services", []):
        print(f"  - {service.get('serviceName')}: ₹{service.get('price')}")
    
    client.close()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python add_ai_cv_service.py <organization_id> [price]")
        print("Example: python add_ai_cv_service.py 692408fc28187fc1976b7499 50.0")
        sys.exit(1)
    
    org_id = sys.argv[1]
    price = float(sys.argv[2]) if len(sys.argv) > 2 else 50.0
    
    asyncio.run(add_ai_cv_service(org_id, price))
