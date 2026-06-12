import os
import platform
import subprocess
import shutil
from mcp.server.fastmcp import FastMCP

# Initialisation du serveur SIFT-Sentinel
mcp = FastMCP("SIFT-F4S-SERVER")

# --- 1. OUTILS DE DIAGNOSTIC ET TRIAGE DE BASE ---

@mcp.tool()
def get_sys_info() -> dict:
    """
    Retrieves system information from the machine currently under analysis.
    Useful for initial triage phase.
    """
    return {
        "os": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "hostname": platform.node()
    }

@mcp.tool()
def list_forensic_directory(target_path: str) -> list:
    """
    Securely lists the files present in a target forensic analysis folder.
    This tool is strictly read-only.
    """
    # Résolution et correction du bug de variable
    absolute_path = os.path.abspath(target_path)
    
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


# --- 2. OUTILS FORENSIQUES ++ ---

@mcp.tool()
def analyze_prefetch_file(prefetch_path: str) -> dict:
    """
    Checks for the existence of a .pf (Prefetch) file and parses it to identify past executions.
    Uses the PECmd tool if available; otherwise, falls back to basic metadata analysis.
    """
    absolute_path = os.path.abspath(prefetch_path)
    
    # 1. Validation défensive de l'extension et de la présence du fichier .pf
    if not os.path.exists(absolute_path) or not absolute_path.endswith('.pf'):
        return {"error": f"Le fichier prefetch spécifié est introuvable ou invalide : {prefetch_path}"}
    
    # 2. Recherche du binaire PECmd (Zimmerman) dans l'environnement SIFT
    pecmd_binary = shutil.which("PECmd") or shutil.which("pecmd")
    
    if pecmd_binary:
        try:
            # Exécution de PECmd avec exportation JSON pour l'analyse structurée de l'IA
            completed_process = subprocess.run([pecmd_binary, "-f", absolute_path, "--json", "/tmp/pf_out"], capture_output=True, text=True, timeout=30)
            return {"status": "success", "tool_used": "PECmd", "output": completed_process.stdout}
        except Exception as exception_error:
            return {"error": f"Erreur lors de l'exécution de PECmd : {str(exception_error)}"}
    else:
        # Fallback de secours sur les métadonnées système si PECmd est absent
        try:
            file_stat = os.stat(absolute_path)
            return {
                "status": "partial_success",
                "message": "PECmd non détecté sur le système. Fallback sur les métadonnées OS.",
                "file_size_bytes": file_stat.st_size,
                "created_time": file_stat.st_ctime,
                "modified_time": file_stat.st_mtime
            }
        except Exception as exception_error:
            return {"error": f"Échec du fallback métadonnées : {str(exception_error)}"}

@mcp.tool()
def run_volatility_pslist(memory_dump_path: str, profile: str = "") -> dict:
    """
    Executes the pslist plugin of Volatility on a memory dump to list active processes.
    Verifies the presence of the memory dump and Volatility beforehand.
    """
    absolute_dump_path = os.path.abspath(memory_dump_path)
    
    # 1. Vérification de la présence du dump mémoire brut
    if not os.path.exists(absolute_dump_path):
        return {"error": f"Le dump mémoire spécifié est introuvable : {memory_dump_path}"}
        
    # 2. Détection de la version de Volatility disponible dans le PATH
    volatility_binary = shutil.which("volatility") or shutil.which("vol.py") or shutil.which("vol")
    
    if not volatility_binary:
        return {"error": "Volatility n'a pas été détecté dans le PATH de cette VM SIFT. Impossible d'analyser la mémoire."}
        
    # 3. Préparation de la commande sécurisée
    command = [volatility_binary, "-f", absolute_dump_path]
    if profile:
        command.extend(["--profile", profile])
        
    # Sélection dynamique du plugin selon le profil renseigné
    command.append("linux.pslist" if "linux" in profile.lower() else "windows.pslist" if profile else "pslist")
    
    try:
        # Exécution avec limite de temps pour éviter de figer l'agent
        completed_process = subprocess.run(command, capture_output=True, text=True, timeout=60)
        
        if completed_process.returncode != 0:
            return {
                "status": "failed",
                "error": completed_process.stderr,
                "suggestion": "Le profil est peut-être incorrect. L'agent doit essayer une autre signature ou utiliser imageinfo."
            }
            
        # Triage économique : extraction des 50 premières lignes pour préserver les tokens de l'IA
        output_lines = completed_process.stdout.split('\n')
        truncated_output = '\n'.join(output_lines[:50])
        
        return {
            "status": "success",
            "tool_used": volatility_binary,
            "total_lines_generated": len(output_lines),
            "output_preview": truncated_output
        }
    except subprocess.TimeoutExpired:
        return {"error": "L'exécution de Volatility a expiré (Timeout de 60s)."}
    except Exception as exception_error:
        return {"error": f"Erreur système lors de l'exécution : {str(exception_error)}"}


# --- 3. LOGIQUE D'ANALYSE DE MENACES AVEC YARA ---

@mcp.tool()
def run_custom_yara_scan(target_path: str, rules_path: str = "~/sift-f4s/sentinel_rules.yar") -> dict:
    """
    Executes a YARA scan on a file or directory using the localized SIFT-Sentinel rule file.
    Ideal for detecting webshells or system binary abuses (GTFOBins).
    """
    # Résolution du dossier d'exécution réel (~/sift-f4s)
    absolute_target = os.path.abspath(os.path.expanduser(target_path))
    absolute_rules = os.path.abspath(os.path.expanduser(rules_path))
    
    if not os.path.exists(absolute_target):
        return {"status": "error", "message": f"La cible à scanner est introuvable : {target_path}"}
        
    if not os.path.exists(absolute_rules):
        return {
            "status": "error", 
            "advice": f"Le fichier de règles YARA n'existe pas à l'emplacement indiqué ({rules_path}). L'agent doit le configurer."
        }
        
    yara_binary = shutil.which("yara")
    if not yara_binary:
        return {"status": "error", "message": "Le binaire 'yara' est introuvable dans l'environnement."}
        
    try:
        completed_process = subprocess.run([yara_binary, absolute_rules, absolute_target], capture_output=True, text=True, timeout=30)
        
        clean_stdout = completed_process.stdout.strip()
        matches_list = clean_stdout.split("\n") if clean_stdout else []
        
        return {
            "status": "success",
            "scan_target": absolute_target,
            "rules_used": absolute_rules,
            "matches_found_count": len(matches_list),
            "detections": matches_list,
            "error_logs": completed_process.stderr.strip() if completed_process.stderr else None
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Le scan YARA a expiré (Timeout dépassé)."}
    except Exception as exception_error:
        return {"status": "error", "message": f"Erreur système : {str(exception_error)}"}


# --- 4. Analyse d'image disk avec Volatility framework 3 ---
@mcp.tool()
def analyze_disk_image_tsk(image_path: str) -> dict:
    """
    Analyzes a raw disk image using The Sleuth Kit (fls) to discover files.
    Specially flags and extracts metadata from deleted files found in the file system.
    """
    absolute_image_path = os.path.abspath(os.path.expanduser(image_path))
    
    # 1. Validation défensive de la présence de l'image disque
    if not os.path.exists(absolute_image_path):
        return {"status": "error", "message": f"L'image disque spécifiée est introuvable : {image_path}"}
        
    # 2. Vérification de la présence de l'outil 'fls' de The Sleuth Kit sur la VM SIFT
    fls_binary = shutil.which("fls")
    if not fls_binary:
        return {"status": "error", "message": "L'outil 'fls' (The Sleuth Kit) n'est pas détecté dans le PATH de la VM."}
        
    try:
        # Exécution de fls :
        # -r : Analyse récursive des répertoires
        # -d : Affiche uniquement les fichiers supprimés (très critique pour l'investigation)
        completed_process = subprocess.run([fls_binary, "-r", "-d", absolute_image_path], capture_output=True, text=True, timeout=45)
        
        if completed_process.returncode != 0:
            return {
                "status": "failed",
                "error": completed_process.stderr.strip(),
                "advice": "Vérifiez que l'image disque n'est pas corrompue et que le système de fichiers est supporté par TSK."
            }
            
        clean_stdout = completed_process.stdout.strip()
        deleted_files = clean_stdout.split("\n") if clean_stdout else []
        
        # Triage économique pour le Context Window de l'IA (limité aux 40 premières lignes)
        return {
            "status": "success",
            "tool_used": "The Sleuth Kit (fls)",
            "image_analyzed": absolute_image_path,
            "total_deleted_files_found": len(deleted_files),
            "deleted_files_preview": deleted_files[:40]
        }
        
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "L'analyse du disque via TSK a expiré (Timeout de 45s)."}
    except Exception as exception_error:
        return {"status": "error", "message": f"Erreur système lors de l'exécution de TSK : {str(exception_error)}"}

if __name__ == "__main__":
    # Démarrage du serveur unifié
    mcp.run()
