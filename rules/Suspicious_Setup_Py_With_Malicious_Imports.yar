rule Suspicious_Setup_Py_With_Malicious_Imports {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup.py with malicious imports and behaviors"
        confidence = 85
        severity = 80

    strings:
        $setup_import = "from setuptools import setup" ascii
        $requests_import = "import requests" ascii
        $subprocess_import = "import subprocess" ascii
        $tempfile_import = "import tempfile" ascii
        $base64_import = "import base64" ascii

    condition:
        $setup_import and 
        any of ($requests_import, $subprocess_import, $tempfile_import, $base64_import)
}