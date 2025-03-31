rule Python_Suspicious_URL_IP {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URL and IP address in Python scripts"
        confidence = 85
        severity = 80

    strings:
        $suspicious_url = "https://minagolosinastorpedolocutormarcar.com/golosinapastortorpedopularie.html"
        $suspicious_ip = "134.209.85.64"

    condition:
        any of ($suspicious_url, $suspicious_ip)
}