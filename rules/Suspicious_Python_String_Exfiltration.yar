rule Suspicious_Python_String_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that sends hardcoded strings to a remote server, potentially for data exfiltration."
        confidence = 80
        severity = 75
    strings:
        $send_string_function = "def send_string(ip, port, message):"
        $sock_sendall = "sock.sendall(message.encode('utf-8'))"
        $hardcoded_message = /message\s*=\s*\"[^\"]+\"/
    condition:
        all of them
}