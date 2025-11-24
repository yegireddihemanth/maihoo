import asyncio
import aiohttp

SUREPASS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc2MzgwMDM0NywianRpIjoiNjA5ZTZmOTctNTcxOS00MjA2LWEwZDAtMjc5ZmFiZTQ0ODQ1IiwidHlwZSI6ImFjY2VzcyIsImlkZW50aXR5IjoiZGV2LnRocmVzaGluZ0BzdXJlcGFzcy5pbyIsIm5iZiI6MTc2MzgwMDM0NywiZXhwIjoyMzk0NTIwMzQ3LCJlbWFpbCI6InRocmVzaGluZ0BzdXJlcGFzcy5pbyIsInRlbmFudF9pZCI6Im1haW4iLCJ1c2VyX2NsYWltcyI6eyJzY29wZXMiOlsidXNlciJdfX0.h90UBZtuKinYF4kjsJ8sGjDR0rtAXNDsDpJwS3bQAEw"

async def post_json(url, headers, payload):
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload, headers=headers) as resp:
            try:
                data = await resp.json()
            except:
                data = await resp.text()
            return {
                "status": resp.status,
                "response": data
            }

async def verify_employment_history(uan_number: str):
    url = "https://kyc-api.surepass.io/api/v1/income/employment-history-uan-v2"

    headers = {
        "Authorization": f"Bearer {SUREPASS_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {"id_number": uan_number}
    return await post_json(url, headers, payload)

async def main():
    uan_number = input("Enter UAN Number: ").strip()
    response = await verify_employment_history(uan_number)
    print("\n--- API Response ---")
    print(response)

if __name__ == "__main__":
    asyncio.run(main())
