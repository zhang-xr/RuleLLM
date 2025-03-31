rule Suspicious_Setup_Install_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious installation hooks in setup.py files"
        confidence = 95
        severity = 95
    
    strings:
        $install_class = "class InstallCommand(install)"
        $cmdclass_pattern = "cmdclass={'install': InstallCommand}"
        $run_method = "def run(self):"
        $install_run = "install.run(self)"
        $subprocess_popen = "subprocess.Popen("
        $os_operations = /os\.(makedirs|chmod|path|expanduser)/
    
    condition:
        all of ($install_class, $cmdclass_pattern, $run_method) and
        any of ($install_run, $subprocess_popen) and
        #os_operations > 2
}