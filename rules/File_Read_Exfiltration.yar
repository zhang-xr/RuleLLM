rule File_Read_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects reading of sensitive files and their potential exfiltration."
        confidence = "90"
        severity = "95"

    strings:
        $os_popen = "os.popen('cat /flag')"
        $base64_encode = "base64.b64encode("
        $http_request = "request(url='http://"

    condition:
        $os_popen and $base64_encode and $http_request
}