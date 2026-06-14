import os
import subprocess
from fastmcp import Client
import asyncio

os.environ.setdefault(
    "VOLATILITY3_CACHE_DIR",
    os.path.join(os.getcwd(), "volatility3-symbols")
)

MEMORY_EXTENSIONS = {
    ".raw", ".mem", ".dmp", ".dump", ".vmem",
    ".mddramimage", ".lime", ".bin"
}

DISK_EXTENSIONS = {
    ".dd", ".img", ".e01", ".001", ".aff",
    ".vhd", ".vhdx", ".vmdk", ".qcow", ".qcow2", ".raw"
}

PREFETCH_EXTENSIONS = { ".pf" }
NETWORK_EXTENSIONS = { ".pcap", ".pcapng", ".cap" }

# Extensions Linux pour Volatility
LINUX_MEMORY_EXTENSIONS = { ".lime", ".mddramimage" }


def collect_targets(evidence_path):
    if os.path.isfile(evidence_path):
        return [evidence_path]
    targets = []
    for root, dirs, files in os.walk(evidence_path):
        for f in files:
            targets.append(os.path.join(root, f))
    return targets


def run_pipeline(evidence_path):
    findings = {}
    print("[*] Starting DFIR pipeline...")

    # =========================
    # 1. SYSTEM INFO
    # =========================
    try:
        findings["system"] = {
            "os": os.uname().sysname,
            "release": os.uname().release,
            "architecture": os.uname().machine,
            "hostname": os.uname().nodename
        }
    except Exception as e:
        findings["system"] = {"error": str(e)}

    # =========================
    # 2. YARA SCAN
    # =========================
    try:
        yara_rule_file = "sentinel_rules.yar"

        # target toujours défini
        target = evidence_path

        yara_cmd = ["yara", "-r", yara_rule_file, target]

        result = subprocess.run(yara_cmd, capture_output=True, text=True)

        findings["yara"] = {
            "status": "success" if result.returncode == 0 else "failed",
            "detections": result.stdout.strip().split("\n") if result.stdout.strip() else [],
            "errors": result.stderr.strip()
        }

    except Exception as e:
        findings["yara"] = {"status": "error", "error": str(e)}

    # =========================
    # 3. MEMORY ANALYSIS
    # =========================
    try:
        # détection Linux/Windows par extension
        ext = os.path.splitext(evidence_path)[1].lower()
        if ext in LINUX_MEMORY_EXTENSIONS:
            vol_plugin = "linux.pslist.PsList"
        else:
            vol_plugin = "windows.info.Info"

        vol_cmd = ["vol", "-f", evidence_path, vol_plugin]

        result = subprocess.run(vol_cmd, capture_output=True, text=True)

        output = result.stdout.strip()
        error = result.stderr.strip()

        findings["memory"] = {
            "status": "success" if output else "partial",
            "output": output[-2000:] if output else "",
            "error": error[-2000:] if error else ""
        }

    except Exception as e:
        findings["memory"] = {
            "status": "skipped",
            "error": str(e),
            "note": "Volatility non disponible"
        }

    # =========================
    # 4. METADATA
    # =========================
    try:
        findings["metadata"] = {
            "evidence": os.path.abspath(evidence_path),
            "extension": os.path.splitext(evidence_path)[1]
        }
    except Exception as e:
        findings["metadata"] = {"error": str(e)}

    print("[*] Pipeline completed.")
    return findings


class ForensicOrchestrator:

    def __init__(self):
        self.client = Client("build2.py")

    async def investigate(self, evidence_path):

        findings = {}
        ext = os.path.splitext(evidence_path)[1].lower()

        async with self.client:

            findings["system"] = await self.client.call_tool("get_sys_info", {})

            findings["metadata"] = {
                "evidence": evidence_path,
                "extension": ext
            }

            findings["yara"] = await self.client.call_tool(
                "run_custom_yara_scan",
                {"target_path": evidence_path}
            )

            if ext in PREFETCH_EXTENSIONS:
                findings["prefetch"] = await self.client.call_tool(
                    "analyze_prefetch_file",
                    {"prefetch_path": evidence_path}
                )
            elif ext in MEMORY_EXTENSIONS:
                findings["memory"] = await self.client.call_tool(
                    "run_volatility_pslist",
                    {"memory_dump_path": evidence_path}
                )
            elif ext in DISK_EXTENSIONS:
                findings["disk"] = await self.client.call_tool(
                    "analyze_disk_image_tsk",
                    {"image_path": evidence_path}
                )
            elif ext in NETWORK_EXTENSIONS:
                findings["network"] = await self.client.call_tool(
                    "analyze_network_dump",
                    {"pcap_path": evidence_path}
                )
            else:
                findings["notice"] = f"Aucun outil spécialisé pour l'extension {ext}"

        return findings


async def main():
    evidence = input("Evidence path: ").strip()
    orchestrator = ForensicOrchestrator()
    findings = await orchestrator.investigate(evidence)
    print("\n===== FINDINGS =====\n")
    print(findings)


if __name__ == "__main__":
    asyncio.run(main())
