from datetime import datetime, timezone
from bson import ObjectId
from utils.email_utils import send_ticket_email


# ------------------------------
# Auto Assignment Logic
# ------------------------------
# async def get_assignee(user, usersCol):
#     role = user.get("role")
#     orgId = str(user.get("organizationId"))

#     # 1. HELPER → ORG_HR
#     if role == "HELPER":
#         return await usersCol.find_one({"organizationId": orgId, "role": "ORG_HR"})

#     # 2. ORG_HR → SPOC
#     if role == "ORG_HR":
#         return await usersCol.find_one({"organizationId": orgId, "role": "SPOC"})

#     # 3. SPOC → SUPER_ADMIN
#     if role == "SPOC":
#         return await usersCol.find_one({"role": "SUPER_ADMIN"})

#     # 4. SUPER_ADMIN → SUPER_SPOC  (FINAL AUTHORITY)
#     if role == "SUPER_ADMIN":
#         return await usersCol.find_one({"role": "SUPER_SPOC"})

#     # 5. SUPER_SPOC → assign to self
#     if role == "SUPER_SPOC":
#         return user

#     return None

async def get_assignee(user, usersCol):

    role = user.get("role")
    userEmail = user.get("email", "").lower().strip()

    # ---------------------------------------------------------
    # CASE A: SUPER ADMINS / GLOBAL SPOC - assign to themselves
    # ---------------------------------------------------------
    if role in ["SUPER_ADMIN", "SUPER_SPOC"]:
        return user

    # ---------------------------------------------------------
    # CASE B: ORG_HR / ORG_SPOC / HELPER
    # Assign to GLOBAL SUPPORT TEAM
    # ---------------------------------------------------------

    # Fetch any super admin or super spoc from BGV
    globalAdmins = await usersCol.find({
        "role": {"$in": ["SUPER_ADMIN", "SUPER_SPOC"]},
        "isActive": True
    }).to_list(length=None)

    if globalAdmins:
        # pick the first super admin / super spoc
        return globalAdmins[0]

    # ---------------------------------------------------------
    # FINAL FALLBACK: assign to the creator if nobody found
    # (should never happen in real situations)
    # ---------------------------------------------------------
    return user

# ------------------------------
# Build ticket object
# ------------------------------
def now():
    return datetime.now(timezone.utc).isoformat()
