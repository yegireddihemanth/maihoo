import asyncio
from apis import run_verification

async def main():
    result = await run_verification(
        "aadhaar_pan_link",
        {
            "aadhaarNumber": "451741335167",

        }
    )
    print(result)

asyncio.run(main())
