rule Malicious_Base64_URL_Construction {
    meta:
        author = "RuleLLM"
        description = "Detects base64-decoded URL construction with hostname concatenation, commonly used in malware for C2 communication."
        confidence = 90
        severity = 80

    strings:
        $b64_decode = "base64.b64decode"
        $url_concat = /url\s*=\s*base64\.b64decode\(.*\)\.decode\(.*\)\s*\+\s*['\"]\?h=.*/
        $hostname = "socket.gethostname()"

    condition:
        all of them
}