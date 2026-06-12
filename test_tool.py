import asyncio
from fastmcp import Client

async def main():

    async with Client("build2.py") as client:

        result = await client.call_tool(
            "get_sys_info",
            {}
        )

        print(result)

asyncio.run(main())
