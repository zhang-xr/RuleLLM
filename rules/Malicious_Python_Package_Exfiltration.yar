rule Malicious_Python_Package_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that attempt to exfiltrate system information via HTTP requests during installation"
        confidence = "90"
        severity = "80"
    
    strings:
        $urls = /http:\/\/[^\s\/]+\/(realtime_p\/pypi\/|)\d{5}/
        $params = /"packagename":\s*"[^"]+",\s*"hostname":\s*"[^"]+",\s*"user":\s*"[^"]+",\s*"path":\s*"[^"]+"/
        $custom_install = "class CrazyInstallStrat(install)"
        $main_call = "from main import main"
        $install_hook = "cmdclass={'install': CrazyInstallStrat,}"
    
    condition:
        all of them
}