rule GitHub_MaliciousPayload {
    meta:
        author = "RuleLLM"
        description = "Detects GitHub URLs used in malicious payloads"
        confidence = 85
        severity = 80

    strings:
        $github_url = /https:\/\/github\.com\/[^\/]+\/[^\/]+\/raw\/[^\/]+\/[^\/]+\.exe/

    condition:
        $github_url
}