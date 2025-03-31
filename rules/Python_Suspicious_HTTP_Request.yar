rule Python_Suspicious_HTTP_Request {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts making suspicious HTTP requests"
        confidence = 80
        severity = 70
    strings:
        // Python script indicators
        $s1 = "import requests"
        $s2 = "import os"
        $s3 = "import socket"
        // HTTP request patterns
        $s4 = "requests.get("
    condition:
        // Match all imports and the HTTP request function
        all of ($s1, $s2, $s3) and $s4
}