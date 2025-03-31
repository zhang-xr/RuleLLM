rule Python_Setup_InfoStealer {
    meta:
        author = "RuleLLM"
        description = "Detects setup.py files that collect and exfiltrate system information"
        confidence = 85
        severity = 75
    strings:
        $ipinfo = "ipinfo.io"
        $data_param = /dataa?=/
        $install_hook = "cmdclass" nocase
        $base64 = "base64"
        $http_get = "requests.get"
        $setup_pattern = "setup.py"
    condition:
        3 of them and 
        $setup_pattern and 
        filesize < 15KB
}