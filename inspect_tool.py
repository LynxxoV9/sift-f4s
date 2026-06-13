from fastmcp import Client
import asyncio

async def main():

    async with Client("build2.py") as client:

        tools = await client.list_tools()

        for tool in tools:
            print("\n===================")
            print(tool.name)
            print(tool.inputSchema)

asyncio.run(main())
