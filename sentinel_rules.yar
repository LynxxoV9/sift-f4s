rule SIFT_F4S_Threat_Detection {
    meta:
        description = "Détecte des indicateurs de compromission : Webshells et traces d'élévation de privilèges (GTFOBins)"
        author = "Lynxxoven - SIFT-Sentinel"
        date = "2026-06-11"
        version = "1.0"

    strings:
        // --- Traces de Webshells suspects ---
        $webshell_1 = "eval(base64_decode" ascii enterprise
        $webshell_2 = "system($_GET[" ascii
        $webshell_3 = "shell_exec(" ascii
        $webshell_4 = "p0wny-shell" ascii nocase

        // --- Traces d'élévation de privilèges (Scripts / Historiques / Logs) ---
        // Abus de binaires systèmes (Patterns issus de GTFOBins pour APT/SUDO)
        $privesc_apt1 = "APT::Update::Pre-Invoke" ascii nocase
        $privesc_apt2 = "apt-get update -o APT::Update::Pre-Invoke" ascii nocase
        $privesc_bash = "/bin/sh -i" ascii
        
    condition:
        // La règle se déclenche si on trouve au moins un indicateur de webshell 
        // OU une commande d'élévation de privilèges suspecte
        any of ($webshell_*) or any of ($privesc_apt*)
}
