rule Python_Package_Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python package setup scripts that exfiltrate system information"
        confidence = 90
        severity = 80
    strings:
        $setup_pattern = "setup("
        $requests_import = "import requests"
        $base64_encode = "base64.b64encode"
        $http_get = "requests.get"
        $install_hook = "cmdclass = {\n\t\t\"install\": "
    condition:
        all of them and
        filesize < 10KB
}