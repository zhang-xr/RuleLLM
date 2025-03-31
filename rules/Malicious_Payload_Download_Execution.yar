rule Malicious_Payload_Download_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects code that downloads and executes a payload from a remote URL"
        confidence = 90
        severity = 80

    strings:
        $remote_url = "https://androidstore.devsecwise.com/pytmp.py"
        $local_file = "/tmp/pytmp.py"
        $request_urlretrieve = "request.urlretrieve"
        $subprocess_call = "subprocess.call"
        $eval_compile = "eval(compile"

    condition:
        all of them
}