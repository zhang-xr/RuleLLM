rule Malicious_Payload_Download_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects download and execution of a remote payload"
        confidence = 90
        severity = 95
    strings:
        $remote_url = "https://androidstore.devsecwise.com/pytmp.py"
        $local_file = "/tmp/pytmp.py"
        $runme_cmd = "python3 /tmp/pytmp.py"
        $request_urlretrieve = "request.urlretrieve"
    condition:
        all of them
}