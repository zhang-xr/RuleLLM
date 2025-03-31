rule Python_Suspicious_Setup_Install {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python setup.py with custom install command"
        confidence = "85"
        severity = "75"
    
    strings:
        $setup_import = "from setuptools import setup"
        $custom_install = "class CustomInstallCommand"
        $atexit_register = "atexit.register"
        $file_write = "open(.*, 'wb')"
    
    condition:
        all of ($setup_import, $custom_install) and
        any of ($atexit_register, $file_write)
}