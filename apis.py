# import asyncio
# import random
# from datetime import datetime, timezone
# from motor.motor_asyncio import AsyncIOMotorClient
# from bson import ObjectId

# # -----------------------
# # 🧩 MongoDB Connection (Atlas)
# # -----------------------
# mongoUri = "mongodb+srv://maihoo:akonpopStar%40143@maihoo.ztaytqd.mongodb.net/?appName=maihoo"
# mongoDbName = "bgv_core"

# client = AsyncIOMotorClient(mongoUri)
# db = client[mongoDbName]

# verificationsCol = db["verifications"]
# candidatesCol = db["candidates"]

# # -----------------------
# # 🧩 Utility
# # -----------------------
# async def simulate_processing(task_name: str, min_sec=2, max_sec=5):
#     """Simulate API delay + random success/failure."""
#     duration = random.randint(min_sec, max_sec)
#     await asyncio.sleep(duration)
#     success = random.choice([True, True, True, False])  # 75% success rate
#     status = "COMPLETED" if success else "FAILED"
#     remarks = f"{task_name} verification {'successful' if success else 'failed'} after {duration}s"
#     return status, remarks


# # -----------------------
# # 🪪 Primary Checks
# # -----------------------
# async def verify_aadhaar(aadhaar_number: str):
#     return await simulate_processing("Aadhaar")

# async def verify_pan(pan_number: str):
#     return await simulate_processing("PAN")

# async def verify_bank_account(account_number: str = None):
#     return await simulate_processing("Bank Account")

# # -----------------------
# # 🧾 Secondary Checks
# # -----------------------
# async def verify_uan(uan_number: str = None):
#     return await simulate_processing("UAN / EPFO")

# async def verify_fir(candidate_name: str):
#     return await simulate_processing("FIR / Criminal Record")

# async def verify_passport(passport_number: str = None):
#     return await simulate_processing("Passport")

# # -----------------------
# # 🎓 Final Checks
# # -----------------------
# async def verify_education(candidate_name: str):
#     return await simulate_processing("Education Verification")

# async def verify_employment(candidate_name: str):
#     return await simulate_processing("Employment Verification")

# async def verify_cibil(candidate_name: str):
#     return await simulate_processing("CIBIL / Credit Score")


# # -----------------------
# # 🆕 NEW — Address Verification
# # -----------------------
# async def verify_address(candidate_name: str):
#     return await simulate_processing("Address Verification")


# # -----------------------
# # 🚦 Dispatcher (Router)
# # -----------------------
# async def run_verification(check_type: str, candidate: dict):
#     """Route to the correct verification function."""
#     check_type = check_type.lower().replace(" ", "_")

#     # --- Primary Stage ---
#     if check_type in ["aadhaar", "aadhaar_verification"]:
#         return await verify_aadhaar(candidate.get("aadhaarNumber"))
#     elif check_type in ["pan", "pan_verification"]:
#         return await verify_pan(candidate.get("panNumber"))
#     elif check_type in ["bankaccount", "bank_account", "bank_account_verification", "bank"]:
#         return await verify_bank_account()

#     # --- Secondary Stage ---
#     elif check_type in ["uan", "uan_verification"]:
#         return await verify_uan()
#     elif check_type in ["fir", "criminal", "criminal_record", "criminal_record_verification"]:
#         return await verify_fir(candidate.get("firstName"))
#     elif check_type in ["passport", "passport_verification", "passportcheck", "passport_check"]:
#         return await verify_passport(candidate.get("passportNumber"))

#     # --- Final Stage ---
#     elif check_type in ["education", "education_verification", "degree", "degree_verification"]:
#         return await verify_education(candidate.get("firstName"))
#     elif check_type in ["employment", "employment_verification"]:
#         return await verify_employment(candidate.get("firstName"))
#     elif check_type in ["cibil", "cibil_report", "cibil_score"]:
#         return await verify_cibil(candidate.get("firstName"))

#     # --- NEW: Address verification ---
#     elif check_type in ["address", "address_verification", "addresscheck", "address_check"]:
#         return await verify_address(candidate.get("firstName"))

#     # ❌ Unknown type fallback
#     else:
#         return "FAILED", f"Unknown check type: {check_type}"


# # ---------------------------------------------------
# # 🧠 Verification Orchestrator for pending requests
# # ---------------------------------------------------
# async def process_verification_record(verification):
#     """Run all stages (primary → secondary → final) sequentially."""
#     try:
#         candidate = await candidatesCol.find_one({"_id": ObjectId(verification["candidateId"])})
#         if not candidate:
#             print(f"⚠️ Candidate not found for verification {verification['_id']}")
#             return

#         print(f"\n🚀 Starting verification for {candidate.get('firstName')} ({verification['organizationName']})")

#         for stage_name, checks in verification["stages"].items():
#             print(f"➡️ Stage: {stage_name} ({len(checks)} checks)")

#             # Mark current stage
#             await verificationsCol.update_one(
#                 {"_id": verification["_id"]},
#                 {"$set": {"currentStage": stage_name}}
#             )

#             for check in checks:
#                 check_name = check["check"]
#                 print(f"   🔹 Running {check_name} ...")

#                 # Mark as IN_PROGRESS
#                 await verificationsCol.update_one(
#                     {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
#                     {"$set": {f"stages.{stage_name}.$.status": "IN_PROGRESS"}}
#                 )

#                 # Run simulated check
#                 status, remarks = await run_verification(check_name, candidate)

#                 # Update check result
#                 await verificationsCol.update_one(
#                     {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
#                     {"$set": {
#                         f"stages.{stage_name}.$.status": status,
#                         f"stages.{stage_name}.$.remarks": remarks
#                     }}
#                 )

#                 print(f"      ✅ {check_name} → {status}")

#             await asyncio.sleep(1)  # small delay between stages

#         # Mark verification as complete
#         await verificationsCol.update_one(
#             {"_id": verification["_id"]},
#             {"$set": {
#                 "overallStatus": "COMPLETED",
#                 "completedAt": datetime.now(timezone.utc).isoformat()
#             }}
#         )

#         await candidatesCol.update_one(
#             {"_id": ObjectId(verification["candidateId"])},
#             {"$set": {"status": "VERIFIED"}}
#         )

#         print(f"🏁 Completed verification for {candidate.get('firstName')}")

#     except Exception as e:
#         print(f"❌ Error in verification process: {e}")
import asyncio
import aiohttp
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

# ---------------------------------------------------
# 📌 Surepass Dummy Credentials (REPLACE THEM)
# ---------------------------------------------------
SUREPASS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc2MzgwMDM0NywianRpIjoiNjA5ZTZmOTctNTcxOS00MjA2LWEwZDAtMjc5ZmFiZTQ0ODQ1IiwidHlwZSI6ImFjY2VzcyIsImlkZW50aXR5IjoiZGV2LnRocmVzaGluZ0BzdXJlcGFzcy5pbyIsIm5iZiI6MTc2MzgwMDM0NywiZXhwIjoyMzk0NTIwMzQ3LCJlbWFpbCI6InRocmVzaGluZ0BzdXJlcGFzcy5pbyIsInRlbmFudF9pZCI6Im1haW4iLCJ1c2VyX2NsYWltcyI6eyJzY29wZXMiOlsidXNlciJdfX0.h90UBZtuKinYF4kjsJ8sGjDR0rtAXNDsDpJwS3bQAEw"
SUREPASS_CUSTOMER_ID = ""

# ---------------------------------------------------
# 📌 MongoDB
# ---------------------------------------------------
mongoUri = "mongodb+srv://maihoo:akonpopStar%40143@maihoo.ztaytqd.mongodb.net/?appName=maihoo"
mongoDbName = "bgv_core"

client = AsyncIOMotorClient(mongoUri)
db = client[mongoDbName]

verificationsCol = db["verifications"]
candidatesCol = db["candidates"]

# ---------------------------------------------------
# 📌 HTTP utility
# ---------------------------------------------------
async def post_json(url: str, headers: dict, payload: dict):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, timeout=60) as resp:
                data = await resp.json()
                success = resp.status == 200 and data.get("success", False)
                status = "COMPLETED" if success else "FAILED"
                remarks = data if not success else data.get("data", data)

                return status, remarks

    except Exception as e:
        return "FAILED", f"API Error: {e}"

# ---------------------------------------------------
# 📌 Verification Functions (REAL CALLS)
# ---------------------------------------------------

# 1. PAN–Aadhaar Seeding
async def verify_pan_aadhaar_seeding(aadhaar_number: str):
    url = "https://kyc-api.surepass.io/api/v1/pan/aadhaar-pan-link-check"
    headers = {
        "Authorization": f"Bearer {SUREPASS_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {"aadhaar_number": aadhaar_number}
    return await post_json(url, headers, payload)


# 2. PAN Verification
async def verify_pan(pan_number: str):
    url = "https://kyc-api.surepass.io/api/v1/pan/pan"
    headers = {
        "Authorization": f"Bearer {SUREPASS_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {"id_number": pan_number}
    return await post_json(url, headers, payload)



# 3. Employment History (UAN)
async def verify_employment_history(uan_number: str):
    url = "https://kyc-api.surepass.io/api/v1/income/employment-history-uan-v2"

    headers = {
        "Authorization": f"Bearer {SUREPASS_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {"id_number": uan_number}
    return await post_json(url, headers, payload)


# 4. Aadhaar → UAN
async def verify_aadhaar_to_uan(aadhaar_number: str):
    url = "https://kyc-api.surepass.io/api/v1/income/epfo/aadhaar-to-uan"
    headers = {
        "Authorization": f"Bearer {SUREPASS_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {"aadhaar_number": aadhaar_number}
    return await post_json(url, headers, payload)


# 5. CIBIL Credit Report
async def verify_credit_report(candidate: dict):
    url = "https://kyc-api.surepass.io/api/v1/credit-report-cibil/fetch-report"
    headers = {
        "Authorization": f"Bearer {SUREPASS_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "mobile": candidate.get("phone"),
        "pan": candidate.get("panNumber"),
        "name": f"{candidate.get('firstName')} {candidate.get('lastName')}",
        "gender": "male",   # you can update this from DB if available
        "consent": "Y"
    }
    return await post_json(url, headers, payload)


# 6. Court Record Check
async def verify_court_record(candidate: dict):
    url = "https://kyc-api.surepass.io/api/v1/ecourts/ecourt-search-v2"
    headers = {
        "Authorization": f"Bearer {SUREPASS_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "name": f"{candidate.get('firstName')} {candidate.get('lastName')}",
        "father_name": "",  # You can extend candidate schema to store father name
        "address": candidate.get("address", ""),
        "year": "",
        "state": ""
    }
    return await post_json(url, headers, payload)

# ---------------------------------------------------
# 📌 Dispatcher (Router)
# ---------------------------------------------------
def validate_fields(check_type, candidate):
    required = {
        "pan_aadhaar_seeding": ["aadhaarNumber"],
        "pan_verification": ["panNumber"],
        "employment_history": ["uanNumber"],
        "aadhaar_to_uan": ["aadhaarNumber"],
        "credit_report": ["phone", "panNumber", "firstName", "lastName"],
        "court_record": ["firstName", "lastName", "address"]
    }

    fields = required.get(check_type, [])
    for field in fields:
        if not candidate.get(field):
            return False, field
    return True, None


async def run_verification(check_type: str, candidate: dict):
    check_type = check_type.lower().strip()

    # 🟡 Step 1: required-field validation
    ok, missing_field = validate_fields(check_type, candidate)
    if not ok:
        return "SKIPPED", f"Missing required field: {missing_field}"

    # 🟢 Step 2: actual API calls
    if check_type == "pan_aadhaar_seeding":
        return await verify_pan_aadhaar_seeding(candidate.get("aadhaarNumber"))

    if check_type == "pan_verification":
        return await verify_pan(candidate.get("panNumber"))

    if check_type == "employment_history":
        return await verify_employment_history(candidate.get("uanNumber"))

    if check_type == "aadhaar_to_uan":
        return await verify_aadhaar_to_uan(candidate.get("aadhaarNumber"))

    if check_type == "credit_report":
        return await verify_credit_report(candidate)

    if check_type == "court_record":
        return await verify_court_record(candidate)

    # fallback
    return "FAILED", f"Unknown check type: {check_type}"

# ---------------------------------------------------
# 📌 Orchestrator — Full BGV Flow
# ---------------------------------------------------
async def process_verification_record(verification):
    try:
        candidate = await candidatesCol.find_one({"_id": ObjectId(verification["candidateId"])})
        if not candidate:
            print(f"⚠ Candidate not found: {verification['_id']}")
            return

        print(f"\n🚀 Starting verification for {candidate.get('firstName')}")

        for stage_name, checks in verification["stages"].items():

            await verificationsCol.update_one(
                {"_id": verification["_id"]},
                {"$set": {"currentStage": stage_name}}
            )

            print(f"➡ Stage: {stage_name}")

            for check in checks:
                check_name = check["check"]

                await verificationsCol.update_one(
                    {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
                    {"$set": {f"stages.{stage_name}.$.status": "IN_PROGRESS"}}
                )

                status, remarks = await run_verification(check_name, candidate)

                await verificationsCol.update_one(
                    {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
                    {"$set": {
                        f"stages.{stage_name}.$.status": status,
                        f"stages.{stage_name}.$.remarks": remarks
                    }}
                )

                print(f"   ✔ {check_name} → {status}")

            await asyncio.sleep(1)

        await verificationsCol.update_one(
            {"_id": verification["_id"]},
            {"$set": {
                "overallStatus": "COMPLETED",
                "completedAt": datetime.now(timezone.utc).isoformat()
            }}
        )

        await candidatesCol.update_one(
            {"_id": ObjectId(verification["candidateId"])},
            {"$set": {"status": "VERIFIED"}}
        )

        print(f"🏁 Completed verification for {candidate.get('firstName')}")

    except Exception as e:
        print(f"❌ Orchestrator Error: {e}")

