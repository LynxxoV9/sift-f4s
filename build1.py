import os
import platform
from mcp.server.fastmcp import FastMCP

#Création d'une instance de serveur MCP:
mcp = FastMCP("SIFT-F4S-SERVER")


#outil 1: Informations systèmes
@mcp.tool()                               #décorateur pour FastMCP
def get_sys_info() -> dict:
    """
    Retrieves sytem information from the machine curently under analysis.
    Usefull for initial triage phase.
    """
    return{
        "OS" : platform.system(),
        "RELEASE" : platform.release(),
        "ARCHITECTURE" : platform.machine(),
        "HOSTNAME" : platform.node()
    }


#outil 2: Lister un repertoire forensic en mode read-only
@mcp.tool()
def list_forensic_dir(target_path:str) -> list:
    """
    Securely lists the files present in a target forensic analysis folder.
    This tool is strictly read-only.
    """
    #Résolution du chemin absolu
    absolu_path = os.path.abspath(target_path)
    #Juste les repertoire autorisés
    if not os.path.exists(absolu_path):
        return [f"Erreur:Le chemin {target_path} n'existe pas"]
    try:
        files = os.listdir(absolu_path)
        result = []
        for file  in files:
            full_file_path = os.path.join(absolu_path, file)
            is_dir = os.path.isdir (full_file_path)
            size = os.path.getsize(full_file_path) if not is_dir else 0
            result.append({
                "name":file,
                "type":"directory" if is_dir else "file",
                "size_bytes":size
            })
        return result
    except Exception as e:
        return [f"Erreur lors de la lecture du repertoire: {str(e)}"]

if __name__ == "__main__":
    #lancement du serveur
    mcp.run()
