# # import asyncio
# # import random
# # from datetime import datetime, timezone
# # from motor.motor_asyncio import AsyncIOMotorClient
# # from bson import ObjectId

# # # -----------------------
# # # 🧩 MongoDB Connection (Atlas)
# # # -----------------------
# # mongoUri = "mongodb+srv://maihoo:akonpopStar%40143@maihoo.ztaytqd.mongodb.net/?appName=maihoo"
# # mongoDbName = "bgv_core"

# # client = AsyncIOMotorClient(mongoUri)
# # db = client[mongoDbName]

# # verificationsCol = db["verifications"]
# # candidatesCol = db["candidates"]

# # # -----------------------
# # # 🧩 Utility
# # # -----------------------
# # async def simulate_processing(task_name: str, min_sec=2, max_sec=5):
# #     """Simulate API delay + random success/failure."""
# #     duration = random.randint(min_sec, max_sec)
# #     await asyncio.sleep(duration)
# #     success = random.choice([True, True, True, False])  # 75% success rate
# #     status = "COMPLETED" if success else "FAILED"
# #     remarks = f"{task_name} verification {'successful' if success else 'failed'} after {duration}s"
# #     return status, remarks


# # # -----------------------
# # # 🪪 Primary Checks
# # # -----------------------
# # async def verify_aadhaar(aadhaar_number: str):
# #     return await simulate_processing("Aadhaar")

# # async def verify_pan(pan_number: str):
# #     return await simulate_processing("PAN")

# # async def verify_bank_account(account_number: str = None):
# #     return await simulate_processing("Bank Account")

# # # -----------------------
# # # 🧾 Secondary Checks
# # # -----------------------
# # async def verify_uan(uan_number: str = None):
# #     return await simulate_processing("UAN / EPFO")

# # async def verify_fir(candidate_name: str):
# #     return await simulate_processing("FIR / Criminal Record")

# # async def verify_passport(passport_number: str = None):
# #     return await simulate_processing("Passport")

# # # -----------------------
# # # 🎓 Final Checks
# # # -----------------------
# # async def verify_education(candidate_name: str):
# #     return await simulate_processing("Education Verification")

# # async def verify_employment(candidate_name: str):
# #     return await simulate_processing("Employment Verification")

# # async def verify_cibil(candidate_name: str):
# #     return await simulate_processing("CIBIL / Credit Score")


# # # -----------------------
# # # 🆕 NEW — Address Verification
# # # -----------------------
# # async def verify_address(candidate_name: str):
# #     return await simulate_processing("Address Verification")


# # # -----------------------
# # # 🚦 Dispatcher (Router)
# # # -----------------------
# # async def run_verification(check_type: str, candidate: dict):
# #     """Route to the correct verification function."""
# #     check_type = check_type.lower().replace(" ", "_")

# #     # --- Primary Stage ---
# #     if check_type in ["aadhaar", "aadhaar_verification"]:
# #         return await verify_aadhaar(candidate.get("aadhaarNumber"))
# #     elif check_type in ["pan", "pan_verification"]:
# #         return await verify_pan(candidate.get("panNumber"))
# #     elif check_type in ["bankaccount", "bank_account", "bank_account_verification", "bank"]:
# #         return await verify_bank_account()

# #     # --- Secondary Stage ---
# #     elif check_type in ["uan", "uan_verification"]:
# #         return await verify_uan()
# #     elif check_type in ["fir", "criminal", "criminal_record", "criminal_record_verification"]:
# #         return await verify_fir(candidate.get("firstName"))
# #     elif check_type in ["passport", "passport_verification", "passportcheck", "passport_check"]:
# #         return await verify_passport(candidate.get("passportNumber"))

# #     # --- Final Stage ---
# #     elif check_type in ["education", "education_verification", "degree", "degree_verification"]:
# #         return await verify_education(candidate.get("firstName"))
# #     elif check_type in ["employment", "employment_verification"]:
# #         return await verify_employment(candidate.get("firstName"))
# #     elif check_type in ["cibil", "cibil_report", "cibil_score"]:
# #         return await verify_cibil(candidate.get("firstName"))

# #     # --- NEW: Address verification ---
# #     elif check_type in ["address", "address_verification", "addresscheck", "address_check"]:
# #         return await verify_address(candidate.get("firstName"))

# #     # ❌ Unknown type fallback
# #     else:
# #         return "FAILED", f"Unknown check type: {check_type}"


# # # ---------------------------------------------------
# # # 🧠 Verification Orchestrator for pending requests
# # # ---------------------------------------------------
# # async def process_verification_record(verification):
# #     """Run all stages (primary → secondary → final) sequentially."""
# #     try:
# #         candidate = await candidatesCol.find_one({"_id": ObjectId(verification["candidateId"])})
# #         if not candidate:
# #             print(f"⚠️ Candidate not found for verification {verification['_id']}")
# #             return

# #         print(f"\n🚀 Starting verification for {candidate.get('firstName')} ({verification['organizationName']})")

# #         for stage_name, checks in verification["stages"].items():
# #             print(f"➡️ Stage: {stage_name} ({len(checks)} checks)")

# #             # Mark current stage
# #             await verificationsCol.update_one(
# #                 {"_id": verification["_id"]},
# #                 {"$set": {"currentStage": stage_name}}
# #             )

# #             for check in checks:
# #                 check_name = check["check"]
# #                 print(f"   🔹 Running {check_name} ...")

# #                 # Mark as IN_PROGRESS
# #                 await verificationsCol.update_one(
# #                     {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
# #                     {"$set": {f"stages.{stage_name}.$.status": "IN_PROGRESS"}}
# #                 )

# #                 # Run simulated check
# #                 status, remarks = await run_verification(check_name, candidate)

# #                 # Update check result
# #                 await verificationsCol.update_one(
# #                     {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
# #                     {"$set": {
# #                         f"stages.{stage_name}.$.status": status,
# #                         f"stages.{stage_name}.$.remarks": remarks
# #                     }}
# #                 )

# #                 print(f"      ✅ {check_name} → {status}")

# #             await asyncio.sleep(1)  # small delay between stages

# #         # Mark verification as complete
# #         await verificationsCol.update_one(
# #             {"_id": verification["_id"]},
# #             {"$set": {
# #                 "overallStatus": "COMPLETED",
# #                 "completedAt": datetime.now(timezone.utc).isoformat()
# #             }}
# #         )

# #         await candidatesCol.update_one(
# #             {"_id": ObjectId(verification["candidateId"])},
# #             {"$set": {"status": "VERIFIED"}}
# #         )

# #         print(f"🏁 Completed verification for {candidate.get('firstName')}")

# #     except Exception as e:
# #         print(f"❌ Error in verification process: {e}")
# import asyncio
# from datetime import datetime, timezone
# from motor.motor_asyncio import AsyncIOMotorClient
# from bson import ObjectId
# import aiohttp
# import ssl
# import certifi

# # ---------------------------------------
# # SSL – FIXED FOR FASTAPI + AIOHTTP
# # ---------------------------------------
# ssl_ctx = ssl.create_default_context(cafile=certifi.where())

# # -------------------------------
# # MongoDB Connection
# # -------------------------------
# mongoUri = "mongodb+srv://maihoo:akonpopStar%40143@maihoo.ztaytqd.mongodb.net/?appName=maihoo"
# mongoDbName = "bgv_core"

# client = AsyncIOMotorClient(mongoUri)
# db = client[mongoDbName]

# verificationsCol = db["verifications"]
# candidatesCol = db["candidates"]

# # -------------------------------
# # Surepass Config
# # -------------------------------
# from config import SUREPASS_TOKEN, SUREPASS_BASE_URL


# # ==========================================================
# # 🔥 FIXED: Surepass API Caller (Works inside FastAPI)
# # ==========================================================
# async def call_surepass_api(endpoint: str, payload: dict):
#     url = f"{SUREPASS_BASE_URL}/{endpoint}"

#     headers = {
#         "Authorization": f"Bearer {SUREPASS_TOKEN}",
#         "Content-Type": "application/json"
#     }

#     async with aiohttp.ClientSession() as session:
#         try:
#             # 🔥 Critical Fix: disable SSL validation inside Uvicorn
#             async with session.post(url, json=payload, headers=headers, ssl=False) as resp:
#                 try:
#                     data = await resp.json()
#                 except:
#                     data = {"error": "Invalid JSON response"}

#                 return {
#                     "status_code": resp.status,
#                     "data": data
#                 }

#         except Exception as e:
#             return {
#                 "status_code": 500,
#                 "error": str(e)
#             }


# # ==========================================================
# # REAL Surepass Checks
# # ==========================================================
# async def check_aadhaar_pan_link(aadhaar_number: str):
#     payload = {
#         "aadhaar_number": aadhaar_number
#     }
#     return await call_surepass_api("pan/aadhaar-pan-link-check", payload)


# async def check_pan_name(pan_number: str, full_name: str = None):
#     payload = {
#         "id_number": pan_number
#     }

#     headers = {
#         "Authorization": f"Bearer {SUREPASS_TOKEN}",
#         "X-Customer-Id": SUREPASS_TOKEN,
#         "Content-Type": "application/json"
#     }

#     url = f"{SUREPASS_BASE_URL}/pan/pan"

#     async with aiohttp.ClientSession() as session:
#         async with session.post(url, json=payload, headers=headers, ssl=ssl_ctx) as resp:
#             try:
#                 data = await resp.json()
#             except:
#                 data = {"error": "Invalid JSON response"}

#             return {
#                 "status_code": resp.status,
#                 "data": data
#             }




# # ==========================================================
# # Dispatcher – ONLY Real Checks Allowed
# # ==========================================================
# async def run_verification(check_type: str, candidate: dict):
#     check_type = check_type.lower().replace(" ", "_")

#     # Aadhaar–PAN link check
#     if check_type in ["aadhaar_pan_link", "aadhaar_pan_check"]:
#         resp = await check_aadhaar_pan_link(candidate.get("aadhaarNumber"))
#         status = "COMPLETED" if resp["status_code"] == 200 else "FAILED"
#         return status, str(resp)

#     # PAN name match
#     if check_type in ["pan_name_check", "pan_name_match"]:
#         resp = await check_pan_name(candidate.get("panNumber"), candidate.get("firstName"))
#         status = "COMPLETED" if resp["status_code"] == 200 else "FAILED"
#         return status, str(resp)

#     # ❌ Everything else is NOT implemented
#     return "FAILED", f"Verification type '{check_type}' not implemented"


# # ==========================================================
# # Orchestrator (background processor)
# # ==========================================================
# async def process_verification_record(verification):
#     """
#     Runs stage-by-stage verification.
#     Uses only the REAL dispatcher above.
#     """

#     try:
#         candidate = await candidatesCol.find_one({"_id": ObjectId(verification["candidateId"])})

#         if not candidate:
#             print(f"⚠ Candidate missing for verification {verification['_id']}")
#             return

#         print(f"\n🚀 Starting verification for {candidate.get('firstName')}")

#         # Loop through stages
#         for stage_name, checks in verification["stages"].items():

#             # Mark stage active
#             await verificationsCol.update_one(
#                 {"_id": verification["_id"]},
#                 {"$set": {"currentStage": stage_name}}
#             )

#             # Run each check
#             for check in checks:
#                 check_name = check["check"]

#                 # Mark check IN_PROGRESS
#                 await verificationsCol.update_one(
#                     {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
#                     {"$set": {f"stages.{stage_name}.$.status": "IN_PROGRESS"}}
#                 )

#                 # Run real Surepass API
#                 status, remarks = await run_verification(check_name, candidate)

#                 # Update DB
#                 await verificationsCol.update_one(
#                     {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
#                     {
#                         "$set": {
#                             f"stages.{stage_name}.$.status": status,
#                             f"stages.{stage_name}.$.remarks": remarks,
#                             f"stages.{stage_name}.$.submittedAt": datetime.now(timezone.utc).isoformat()
#                         }
#                     }
#                 )

#             await asyncio.sleep(0.05)

#         # Mark verification complete
#         await verificationsCol.update_one(
#             {"_id": verification["_id"]},
#             {
#                 "$set": {
#                     "overallStatus": "COMPLETED",
#                     "completedAt": datetime.now(timezone.utc).isoformat()
#                 }
#             }
#         )

#         await candidatesCol.update_one(
#             {"_id": ObjectId(verification["candidateId"])},
#             {"$set": {"status": "VERIFIED"}}
#         )

#         print(f"🏁 Verification completed for {candidate.get('firstName')}")

#     except Exception as e:
#         print(f"❌ Error in verification: {e}")
import asyncio
import random
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

# -----------------------
# 🧩 MongoDB Connection (Atlas)
# -----------------------
mongoUri = "mongodb+srv://maihoo:akonpopStar%40143@maihoo.ztaytqd.mongodb.net/?appName=maihoo"
mongoDbName = "bgv_core"

client = AsyncIOMotorClient(mongoUri)
db = client[mongoDbName]

verificationsCol = db["verifications"]
candidatesCol = db["candidates"]

# -----------------------
# 🧩 Utility
# -----------------------
async def simulate_processing(task_name: str, min_sec=2, max_sec=5):
    """Simulate API delay + random success/failure."""
    duration = random.randint(min_sec, max_sec)
    await asyncio.sleep(duration)
    success = random.choice([True, True, True, False])  # 75% success rate
    status = "COMPLETED" if success else "FAILED"
    remarks = f"{task_name} verification {'successful' if success else 'failed'} after {duration}s"
    return status, remarks


# -----------------------
# 🪪 Primary Checks
# -----------------------
async def verify_aadhaar(aadhaar_number: str):
    return await simulate_processing("Aadhaar")

async def verify_pan(pan_number: str):
    return await simulate_processing("PAN")

async def verify_bank_account(account_number: str = None):
    return await simulate_processing("Bank Account")

# -----------------------
# 🧾 Secondary Checks
# -----------------------
async def verify_uan(uan_number: str = None):
    return await simulate_processing("UAN / EPFO")

async def verify_fir(candidate_name: str):
    return await simulate_processing("FIR / Criminal Record")

async def verify_passport(passport_number: str = None):
    return await simulate_processing("Passport")

# -----------------------
# 🎓 Final Checks
# -----------------------
async def verify_education(candidate_name: str):
    return await simulate_processing("Education Verification")

async def verify_employment(candidate_name: str):
    return await simulate_processing("Employment Verification")

async def verify_cibil(candidate_name: str):
    return await simulate_processing("CIBIL / Credit Score")


# -----------------------
# 🆕 NEW — Address Verification
# -----------------------
async def verify_address(candidate_name: str):
    return await simulate_processing("Address Verification")


# -----------------------
# 🚦 Dispatcher (Router)
# -----------------------
async def run_verification(check_type: str, candidate: dict):
    """Route to the correct verification function."""
    check_type = check_type.lower().replace(" ", "_")

    # --- Primary Stage ---
    if check_type in ["aadhaar", "aadhaar_verification"]:
        return await verify_aadhaar(candidate.get("aadhaarNumber"))
    elif check_type in ["pan", "pan_verification"]:
        return await verify_pan(candidate.get("panNumber"))
    elif check_type in ["bankaccount", "bank_account", "bank_account_verification", "bank"]:
        return await verify_bank_account()

    # --- Secondary Stage ---
    elif check_type in ["uan", "uan_verification"]:
        return await verify_uan()
    elif check_type in ["fir", "criminal", "criminal_record", "criminal_record_verification"]:
        return await verify_fir(candidate.get("firstName"))
    elif check_type in ["passport", "passport_verification", "passportcheck", "passport_check"]:
        return await verify_passport(candidate.get("passportNumber"))

    # --- Final Stage ---
    elif check_type in ["education", "education_verification", "degree", "degree_verification"]:
        return await verify_education(candidate.get("firstName"))
    elif check_type in ["employment", "employment_verification"]:
        return await verify_employment(candidate.get("firstName"))
    elif check_type in ["cibil", "cibil_report", "cibil_score"]:
        return await verify_cibil(candidate.get("firstName"))

    # --- NEW: Address verification ---
    elif check_type in ["address", "address_verification", "addresscheck", "address_check"]:
        return await verify_address(candidate.get("firstName"))

    # ❌ Unknown type fallback
    else:
        return "FAILED", f"Unknown check type: {check_type}"


# ---------------------------------------------------
# 🧠 Verification Orchestrator for pending requests
# ---------------------------------------------------
async def process_verification_record(verification):
    """Run all stages (primary → secondary → final) sequentially."""
    try:
        candidate = await candidatesCol.find_one({"_id": ObjectId(verification["candidateId"])})
        if not candidate:
            print(f"⚠️ Candidate not found for verification {verification['_id']}")
            return

        print(f"\n🚀 Starting verification for {candidate.get('firstName')} ({verification['organizationName']})")

        for stage_name, checks in verification["stages"].items():
            print(f"➡️ Stage: {stage_name} ({len(checks)} checks)")

            # Mark current stage
            await verificationsCol.update_one(
                {"_id": verification["_id"]},
                {"$set": {"currentStage": stage_name}}
            )

            for check in checks:
                check_name = check["check"]
                print(f"   🔹 Running {check_name} ...")

                # Mark as IN_PROGRESS
                await verificationsCol.update_one(
                    {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
                    {"$set": {f"stages.{stage_name}.$.status": "IN_PROGRESS"}}
                )

                # Run simulated check
                status, remarks = await run_verification(check_name, candidate)

                # Update check result
                await verificationsCol.update_one(
                    {"_id": verification["_id"], f"stages.{stage_name}.check": check_name},
                    {"$set": {
                        f"stages.{stage_name}.$.status": status,
                        f"stages.{stage_name}.$.remarks": remarks
                    }}
                )

                print(f"      ✅ {check_name} → {status}")

            await asyncio.sleep(1)  # small delay between stages

        # Mark verification as complete
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
        print(f"❌ Error in verification process: {e}")