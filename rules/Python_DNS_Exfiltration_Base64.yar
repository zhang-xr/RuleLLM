rule Python_DNS_Exfiltration_Base64 {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that constructs Base64 encoded subdomains for potential DNS exfiltration"
        confidence = 85
        severity = 80
    strings:
        $base64_decode = "base64.b64decode"
        $base64_encode = "base64.urlsafe_b64encode"
        $subdomain_construct = /f"{[^}]+}\.{[^}]+}"/ ascii
        $gethostbyname = "gethostbyname"
    condition:
        all of ($base64_decode, $base64_encode) and 
        $subdomain_construct and 
        $gethostbyname
}