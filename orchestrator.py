from fastmcp import Client
import asyncio

class ForensicOrchestrator:

    def __init__(self):
        self.client = Client("build2.py")

    async def investigate(self, evidence_path):

        findings = {}

        async with self.client:

            findings["system"] = await self.client.call_tool(
                "get_sys_info",
                {}
            )

            findings["files"] = await self.client.call_tool(
                "list_forensic_directory",
                {
                    "target_path": "."
                }
            )

            #--- Volatility ---
            findings["processes"] = await self.client.call_tool(
                "run_volatility_pslist",
                {
                    "memory_image": evidence_path
                }
            )

            #--- TSK ---
            findings["disk"] = await self.client.call_tool(
                "analyze_disk_image_tsk",
                {
                    "image_path": evidence_path
                }
            )

            #--- YARA ---
            findings["yara"] = await self.client.call_tool(
                "run_custom_yara_scan",
                {
                    "target_path": evidence_path,
                    "rule_file": "sentinel_rules.yar"
                }
            )

        return findings


# Test1
async def main():

    orchestrator = ForensicOrchestrator()

    report = await orchestrator.investigate(
        "/home/sansforensics/sift-f4s/uploads/pat-2009-11-18.mddramimage"
    )

    print(report)

asyncio.run(main())
