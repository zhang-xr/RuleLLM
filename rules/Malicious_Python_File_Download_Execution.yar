rule Malicious_Python_File_Download_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that download and execute files from external URLs."
        confidence = 85
        severity = 75

    strings:
        $requests_get = /requests\.get\([^)]+\)/
        $tempfile = /tempfile\.NamedTemporaryFile\(/
        $subprocess_call = /subprocess\.call\([^)]+\)/
        $url_pattern = /https?:\/\/[^\s]+\/(Windows|payload|malware)\.(exe|dll|bat)/

    condition:
        $requests_get and $tempfile and $subprocess_call and $url_pattern
}