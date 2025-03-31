rule Python_Crypter_Remote_Payload_Download {
    meta:
        author = "RuleLLM"
        description = "Detects Python-based crypter that downloads and executes a remote payload."
        confidence = 90
        severity = 85

    strings:
        $remote_url = "https://androidstore.devsecwise.com/pytmp.py"
        $local_file = "/tmp/pytmp.py"
        $request_urlretrieve = "request.urlretrieve"
        $subprocess_call = "subprocess.call"
        $eval_compile = "eval(compile"

    condition:
        all of them
}