rule Dynamic_URL_Sensitive_Data {
    meta:
        author = "RuleLLM"
        description = "Detects dynamic URL construction with sensitive system information"
        confidence = 85
        severity = 75
    strings:
        // Patterns for dynamic URL construction
        $s1 = "gethostname()"
        $s2 = "os.uname()"
        $s3 = "os.getcwd()"
        $s4 = /http:\/\/.*\?.*=.*&.*=.*&.*=.*/
    condition:
        // Match at least 2 system info patterns and the URL query structure
        (2 of ($s1, $s2, $s3)) and $s4
}