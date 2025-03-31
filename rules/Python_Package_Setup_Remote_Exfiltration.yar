rule Python_Package_Setup_Remote_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with setup.py that perform remote data exfiltration"
        confidence = 90
        severity = 85
    strings:
        $setup_import = "import setuptools"
        $urllib_import = "import urllib.request"
        $urlopen = "urllib.request.urlopen"
        $urlencode = "urllib.parse.urlencode"
        $cmdclass = "cmdclass={"
    condition:
        $setup_import and $urllib_import and 
        any of ($urlopen, $urlencode) and 
        $cmdclass
}