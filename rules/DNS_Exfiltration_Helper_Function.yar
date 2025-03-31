rule DNS_Exfiltration_Helper_Function {
    meta:
        author = "RuleLLM"
        description = "Detects DNS request helper functions used for data exfiltration"
        confidence = 95
        severity = 85
    strings:
        $dns_func1 = "def dns_request("
        $dns_func2 = "with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:"
        $dns_func3 = "s.sendto(request, addr)"
        $dns_func4 = "s.recvfrom(4096)"
    condition:
        $dns_func1 and 
        (2 of ($dns_func2, $dns_func3, $dns_func4))
}