rule Suspicious_Setup_Py_Configuration {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup.py configurations often used in malicious Python packages."
        confidence = 85
        severity = 85

    strings:
        $setuptools_import = "from setuptools import setup, find_packages"
        $install_requires_empty = "install_requires=['']"
        $suspicious_keywords = "keywords=['python','arg','args','print','nagogy','echo']"

    condition:
        all of them
}