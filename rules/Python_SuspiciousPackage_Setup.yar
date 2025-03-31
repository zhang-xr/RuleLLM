rule Python_SuspiciousPackage_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package setup configurations with execution hooks"
        confidence = 85
        severity = 75
    strings:
        $setup_hook = "cmdclass"
        $exec_hook1 = "PostDevelopCommand"
        $exec_hook2 = "PostInstallCommand"
        $exec_method = "def execute():"
        $system_call = "os.system"
    condition:
        all of ($setup_hook, $exec_method) and 
        any of ($exec_hook*) and 
        $system_call
}