rule Python_Malicious_InstallHook {
    meta:
        author = "RuleLLM"
        description = "Detects malicious install hooks in Python setup files"
        confidence = 95
        severity = 85
    strings:
        $install_class = /class\s+\w+InstallCommand.*install/
        $run_method = "def run(self):"
        $install_run = "install.run(self)"
        $custom_code = /requests\.get\(.*\)/
    condition:
        all of ($install_class, $run_method, $install_run) and 
        1 of ($custom_code) and 
        filesize < 20KB
}