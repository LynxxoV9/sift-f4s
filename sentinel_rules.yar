rule SIFT_F4S_Threat_Detection
{
    meta:
        description = "Detect webshell and privilege escalation indicators"
        author = "Lynxxoven - SIFT-Sentinel"
        date = "2026-06-11"
        version = "1.0"

    strings:

        $webshell_1 = "eval(base64_decode" ascii nocase
        $webshell_2 = "system($_GET[" ascii
        $webshell_3 = "shell_exec(" ascii
        $webshell_4 = "p0wny-shell" ascii nocase

        $privesc_apt1 = "APT::Update::Pre-Invoke" ascii nocase
        $privesc_apt2 = "apt-get update -o APT::Update::Pre-Invoke" ascii nocase
        $privesc_bash = "/bin/sh -i" ascii

    condition:
        any of ($webshell_*) or
        any of ($privesc_*)
}
