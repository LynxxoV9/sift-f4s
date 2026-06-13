import asyncio
from fastmcp import Client

async def main():

    async with Client("build2.py") as client:

        result = await client.call_tool(
            "analyze_disk_image_tsk",
            {
                "image_path": "/home/sansforensics/sift-f4s/uploads/pat-2009-11-18.mddramimage"
            }
        )


        print(result)

asyncio.run(main())
