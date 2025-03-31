rule Python_SuspiciousCustomInstall {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious custom install commands in Python setup scripts"
        confidence = "80"
        severity = "75"
    
    strings:
        $custom_install = "class CustomInstallCommand"
        $cmdclass_setup = "cmdclass={'install': CustomInstallCommand}"
        $empty_class = "class send():"
        $empty_function = "def __init__():"
    
    condition:
        all of ($custom_install, $cmdclass_setup) and 
        (1 of ($empty_class, $empty_function))
}