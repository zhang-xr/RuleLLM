rule Malicious_Python_Package_Behavior {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with malicious installation behavior and suspicious metadata"
        confidence = "90"
        severity = "85"

    strings:
        $abort_message = "[+] It looks like you try to install"
        $suspicious_url = "http://evilpackage.fatezero.org/"
        $install_class = "class AbortInstall(install):"
        $system_exit = "raise SystemExit"
        $package_name = /name\s*=\s*["']us[a-z]r_agent["']/
        $author_email = /author_email\s*=\s*["']root@gmail.com["']/
        $cmd_class = /cmdclass\s*=\s*\{['"]install['"]:\s*AbortInstall\}/

    condition:
        (all of ($abort_message, $suspicious_url, $install_class, $system_exit)) or
        (all of ($suspicious_url, $package_name) and any of ($author_email, $cmd_class))
}