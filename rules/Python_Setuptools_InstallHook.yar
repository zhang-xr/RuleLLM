rule Python_Setuptools_InstallHook {
    meta:
        author = "RuleLLM"
        description = "Detects malicious use of setuptools install hooks"
        confidence = "85"
        severity = "90"
    
    strings:
        $setup_import = "from setuptools import setup"
        $install_import = "from setuptools.command.install import install"
        $cmdclass_dict = "cmdclass={"
        $post_install = "PostInstallCommand"
        
    condition:
        all of ($setup_import, $install_import) and
        any of ($cmdclass_dict, $post_install)
}