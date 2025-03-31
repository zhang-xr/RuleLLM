rule Malicious_File_Download_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects downloading and execution of a remote executable file"
        confidence = 95
        severity = 100
    strings:
        $requests_get = "requests.get"
        $tempfile = "tempfile.NamedTemporaryFile"
        $subprocess_call = "subprocess.call"
    condition:
        all of them
}