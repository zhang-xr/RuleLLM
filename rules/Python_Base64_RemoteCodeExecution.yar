rule Python_Base64_RemoteCodeExecution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using base64 encoded payload for remote code execution"
        confidence = 95
        severity = 90
    strings:
        $import_chain = "__import__('builtins').exec(__import__('builtins').compile(__import__('base64').b64decode"
        $url_pattern = /http:\/\/[\d\.]+\/\w+\/\w+/
        $tempfile_pattern = /_ttmp\s*=\s*_ffile\(delete=False\)/
        $exec_pattern = "_ssystem(f\"start {_eexecutable.replace('.exe', 'w.exe')} {_ttmp.name}\")"
    condition:
        all of them
}