rule Python_Setup_Command_Override {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious command class overrides in Python setup scripts"
        confidence = 85
        severity = 80
        reference = "Analyzed code segment"
    
    strings:
        $install_override = "cmdclass={ 'install':"
        $develop_override = "'develop':"
        $egg_info_override = "'egg_info':"
        $custom_class = "class Custom"
        $setup_import = "from setuptools import setup"
    
    condition:
        filesize < 10KB and
        all of ($setup_import, $custom_class) and
        2 of ($install_override, $develop_override, $egg_info_override)
}