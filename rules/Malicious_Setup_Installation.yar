rule Malicious_Setup_Installation {
    meta:
        author = "RuleLLM"
        description = "Detects the setup and installation of potentially malicious Python packages"
        confidence = 80
        severity = 70

    strings:
        $setup_import = "from setuptools import setup"
        $install_requires = "install_requires"
        $malicious_keywords = /crypter|avbypass|crypt/

    condition:
        all of them
}