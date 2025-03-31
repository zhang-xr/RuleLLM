rule Malicious_GitHub_Download {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious file downloads from GitHub repositories"
        confidence = 80
        severity = 75
    strings:
        $github_url = "github.com" nocase
        $raw_content = "raw/master/"
        $executable = ".exe"
    condition:
        all of ($github_url, $raw_content, $executable)
}