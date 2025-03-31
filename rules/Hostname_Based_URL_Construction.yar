rule Hostname_Based_URL_Construction {
    meta:
        author = "RuleLLM"
        description = "Detects URL construction using the hostname, commonly used in malware for C2 communication or data exfiltration."
        confidence = 85
        severity = 75

    strings:
        $hostname = "socket.gethostname()"
        $url_construction = /url\s*=\s*.*\s*\+\s*['\"]\?h=.*/

    condition:
        all of them
}