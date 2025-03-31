rule Malicious_Network_Communication {
    meta:
        author = "RuleLLM"
        description = "Detects network communication with dynamically constructed URLs"
        confidence = 95
        severity = 85

    strings:
        $b64_decode = "base64.b64decode"
        $urlopen = "urllib.request.urlopen"
        $hostname = "socket.gethostname()"

    condition:
        all of them
}