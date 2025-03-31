rule Python_Install_Hook_Backdoor {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package installation hook patterns"
        confidence = "85"
        severity = "90"
    strings:
        $cmdclass_pattern = "cmdclass={'install':"
        $custom_install_class = "class CustomInstallCommand"
        $empty_class = "class send():"
        $empty_init = "def __init__():"
    condition:
        ($cmdclass_pattern and $custom_install_class) or 
        ($empty_class and $empty_init)
}