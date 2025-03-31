rule Malicious_Environment_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects environment variables and exfiltrates them via HTTP POST"
        confidence = 95
        severity = 90

    strings:
        $env_collection = "os.environ"  // Collects environment variables
        $urlencode = "urllib.parse.urlencode"  // Encodes data for HTTP POST
        $urlopen = "urllib.request.urlopen"  // Sends data to remote server
        $content_type = "application/x-www-form-urlencoded"  // HTTP POST header

    condition:
        all of them and filesize < 10KB
}