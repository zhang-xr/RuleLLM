rule Python_Malicious_Package_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package using setuptools"
        confidence = 75
        severity = 80

    strings:
        $setuptools_import = "from setuptools import setup"
        $install_class = "class execute(install)"
        $cmdclass = "cmdclass={'install': execute}"

    condition:
        all of ($setuptools_import, $install_class, $cmdclass)
}