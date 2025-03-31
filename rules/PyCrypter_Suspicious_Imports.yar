rule PyCrypter_Suspicious_Imports {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious imports and setup configurations in Python scripts"
        confidence = 85
        severity = 75
    strings:
        $setup = "from setuptools import setup, find_packages"
        $install_requires = "install_requires=['termcolor', 'request', 'random']"
        $description = "Python Crypter For Red Teaming"
        $setuptools_version = "VERSION = '1.0.12'"
    condition:
        3 of them
}