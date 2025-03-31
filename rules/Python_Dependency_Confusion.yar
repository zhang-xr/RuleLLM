rule Python_Dependency_Confusion {
    meta:
        author = "RuleLLM"
        description = "Detects potential dependency confusion patterns in Python packages"
        confidence = 80
        severity = 70
    strings:
        $setup_func = "setup("
        $package_name = /name=['"][a-zA-Z0-9-_]+['"]/
        $cmdclass = "cmdclass={'install': CustomInstallCommand,}"
        $custom_install = "class CustomInstallCommand(install)"
    condition:
        all of ($setup_func, $package_name) and 
        any of ($cmdclass, $custom_install)
}