rule Python_SuspiciousSetup_Structure {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup.py structure with custom install command"
        confidence = 90
        severity = 85
    strings:
        $setup_import = "from setuptools import setup"
        $install_import = "from setuptools.command.install import install"
        $custom_install = "class InstallCommand(install):"
        $try_except = "try:"
        $except_pass = "except: pass"
    condition:
        3 of ($setup_import, $install_import, $custom_install, $try_except, $except_pass) and filesize < 10KB
}