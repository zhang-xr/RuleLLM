rule Python_Setup_DataExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setup.py files with data exfiltration capabilities"
        confidence = 90
        severity = 80
    strings:
        $url_pattern = /https?:\/\/[^\s]+\?oe-extract-ids\d{0,3}/
        $base64_encode = "base64.b64encode"
        $custom_install = "class CustomInstallCommand"
        $setup_pattern = "setup("
        $requests_import = "import requests"
    condition:
        all of them and 
        filesize < 10KB
}