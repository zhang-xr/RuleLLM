rule Malicious_PostInstall_Script {
    meta:
        author = "RuleLLM"
        description = "Detects malicious PostInstall script in Python setup tools"
        confidence = 90
        severity = 85
    strings:
        $cmdclass = "cmdclass" 
        $postinstall = "PostInstallScript" 
        $run_method = "def run(self):"
        $sys_path = "sys.path.insert"
    condition:
        $cmdclass and $postinstall and $run_method and $sys_path
}