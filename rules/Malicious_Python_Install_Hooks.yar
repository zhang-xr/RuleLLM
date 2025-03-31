rule Malicious_Python_Install_Hooks {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with malicious installation hooks"
        confidence = 85
        severity = 75
        
    strings:
        $develop_hook = "class PostDevelopCommand(develop)"
        $install_hook = "class PostInstallCommand(install)"
        $cmdclass = "cmdclass={"
        $execute_func = "def execute():"
        
    condition:
        all of them and
        filesize < 10KB
}