rule Malicious_Base64_URL_Construction {
    meta:
        author = "RuleLLM"
        description = "Detects base64 URL construction commonly used in malicious scripts"
        confidence = 90
        severity = 80
    strings:
        $base64_decode = "base64.b64decode"
        $url_construction = /url\s*=\s*base64\.b64decode\(.*\)\.decode\(.*\)/
        $hostname_check = /f'\?h=\{hostname\}'/
    condition:
        all of them
}