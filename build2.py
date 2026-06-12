import os
import platform
import subprocess
import shutil
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("SIFT-F4S-SERVER")


# --- 1. OUTILS DE DIAGNOSTIC ET TRIAGE ---

@mcp.tool()
def get_sys_info() -> dict:
    return {
        "os": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "hostname": platform.node()
    }


@mcp.tool()
def list_forensic_directory(target_path: str) -> list:
    absolute_path = os.path.abspath(os.path.expanduser(target_path))

    if not os.path.exists(absolute_path):
        return [f"Erreur : Le chemin {target_path} n'existe pas."]

    try:
        files = os.listdir(absolute_path)
        result = []

        for file in files:
            full_file_path = os.path.join(absolute_path, file)
            is_dir = os.path.isdir(full_file_path)
            size = os.path.getsize(full_file_path) if not is_dir else 0

            result.append({
                "name": file,
                "type": "directory" if is_dir else "file",
                "size_bytes": size
            })

        return result

    except Exception as exception_error:
        return [f"Erreur lors de la lecture du répertoire : {str(exception_error)}"]


# --- 2. PREFETCH ANALYSIS ---

@mcp.tool()
def analyze_prefetch_file(prefetch_path: str) -> dict:
    absolute_path = os.path.abspath(os.path.expanduser(prefetch_path))

    if not os.path.exists(absolute_path) or not absolute_path.endswith('.pf'):
        return {"error": f"Fichier invalide : {prefetch_path}"}

    pecmd_binary = shutil.which("PECmd") or shutil.which("pecmd")

    if pecmd_binary:
        try:
            completed_process = subprocess.run(
                [pecmd_binary, "-f", absolute_path, "--json", "/tmp/pf_out"],
                capture_output=True,
                text=True,
                timeout=30
            )

            return {
                "status": "success",
                "tool_used": "PECmd",
                "output": completed_process.stdout
            }

        except Exception as exception_error:
            return {"error": str(exception_error)}

    try:
        file_stat = os.stat(absolute_path)
        return {
            "status": "partial_success",
            "file_size_bytes": file_stat.st_size,
            "created_time": file_stat.st_ctime,
            "modified_time": file_stat.st_mtime
        }

    except Exception as exception_error:
        return {"error": str(exception_error)}


# --- 3. VOLATILITY ---

@mcp.tool()
def run_volatility_pslist(memory_dump_path: str, profile: str = "") -> dict:
    absolute_dump_path = os.path.abspath(memory_dump_path)

    if not os.path.exists(absolute_dump_path):
        return {"error": "Dump introuvable"}

    volatility_binary = shutil.which("volatility") or shutil.which("vol.py") or shutil.which("vol")

    if not volatility_binary:
        return {"error": "Volatility introuvable"}

    command = [volatility_binary, "-f", absolute_dump_path]

    if profile:
        command.extend(["--profile", profile])

    command.append(
        "linux.pslist"
        if "linux" in profile.lower()
        else "windows.pslist"
        if profile
        else "pslist"
    )

    try:
        completed_process = subprocess.run(command, capture_output=True, text=True, timeout=60)

        if completed_process.returncode != 0:
            return {
                "status": "failed",
                "error": completed_process.stderr
            }

        output_lines = completed_process.stdout.split("\n")

        return {
            "status": "success",
            "tool_used": volatility_binary,
            "output_preview": "\n".join(output_lines[:50])
        }

    except Exception as exception_error:
        return {"error": str(exception_error)}


# --- 4. YARA ---

@mcp.tool()
def run_custom_yara_scan(target_path: str, rules_path: str = "~/sift-f4s/sentinel_rules.yar") -> dict:
    absolute_target = os.path.abspath(os.path.expanduser(target_path))
    absolute_rules = os.path.abspath(os.path.expanduser(rules_path))

    if not os.path.exists(absolute_target):
        return {"status": "error", "message": "cible introuvable"}

    if not os.path.exists(absolute_rules):
        return {"status": "error", "message": "rules introuvable"}

    yara_binary = shutil.which("yara")

    if not yara_binary:
        return {"status": "error", "message": "yara introuvable"}

    try:
        completed_process = subprocess.run(
            [yara_binary, absolute_rules, absolute_target],
            capture_output=True,
            text=True,
            timeout=30
        )

        output = completed_process.stdout + completed_process.stderr
        matches = [line for line in output.split("\n") if line.strip()]

        return {
            "status": "success",
            "detections": matches
        }

    except Exception as exception_error:
        return {"status": "error", "message": str(exception_error)}


# --- 5. NOUVEL OUTIL : ANALYSE PCAP / DUMP RÉSEAU ---

@mcp.tool()
def analyze_network_dump(pcap_path: str) -> dict:
    absolute_path = os.path.abspath(os.path.expanduser(pcap_path))

    if not os.path.exists(absolute_path):
        return {"status": "error", "message": "PCAP introuvable"}

    tshark_binary = shutil.which("tshark")

    if not tshark_binary:
        return {"status": "error", "message": "tshark non installé"}

    try:
        command = [
            tshark_binary,
            "-r",
            absolute_path,
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "tcp.port"
        ]

        completed_process = subprocess.run(command, capture_output=True, text=True, timeout=60)

        lines = completed_process.stdout.split("\n")

        return {
            "status": "success",
            "tool_used": "tshark",
            "total_packets": len(lines),
            "preview": lines[:50]
        }

    except Exception as exception_error:
        return {"status": "error", "message": str(exception_error)}


if __name__ == "__main__":
    mcp.run()
