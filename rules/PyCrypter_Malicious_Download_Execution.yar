rule PyCrypter_Malicious_Download_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python code downloading and executing remote payloads"
        confidence = 95
        severity = 90
    strings:
        $remote_url = "https://androidstore.devsecwise.com/pytmp.py"
        $local_file = "/tmp/pytmp.py"
        $request_urlretrieve = "request.urlretrieve"
        $subprocess_call = "subprocess.call"
        $runme = "def runme():"
        $goodwork = "def goodwork():"
    condition:
        all of them
}