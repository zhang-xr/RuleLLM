rule Repeated_Suspicious_URL {
    meta:
        author = "RuleLLM"
        description = "Detects repeated suspicious URLs in Python code"
        confidence = 95
        severity = 85
    strings:
        $url1 = "http://evilpackage.fatezero.org/" nocase
        $url2 = "http://evilpackage.fatezero.org/" nocase
        $url3 = "http://evilpackage.fatezero.org/" nocase
    condition:
        #url1 >= 3 or #url2 >= 3 or #url3 >= 3
}