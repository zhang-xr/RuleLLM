rule Base64_Encoded_IP_Port {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoded IP and port strings in Python scripts"
        confidence = 90
        severity = 85

    strings:
        $encoded_host = "NDkuMjMzLjEyMS41Mw=="
        $encoded_port = "NTQ="
        $base64_decode = "base64.b64decode("
        $socket_connect = "s.connect("

    condition:
        all of ($encoded_host, $encoded_port, $base64_decode) and
        $socket_connect
}