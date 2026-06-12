import asyncio
from fastmcp import Client

async def main():

    async with Client("build2.py") as client:

        tools = await client.list_tools()

        print("\n===|||- TOOLS -|||===")

        for tool in tools:
            print(tool.name)

asyncio.run(main())
