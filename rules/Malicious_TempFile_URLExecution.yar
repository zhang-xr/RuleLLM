rule Malicious_TempFile_URLExecution {
    meta:
        author = "RuleLLM"
        description = "Detects creation of temporary files containing code to download and execute remote scripts."
        confidence = 90
        severity = 85

    strings:
        $tempfile_create = "NamedTemporaryFile(delete=False)"
        $urlopen_exec = /urllib\.request\.urlopen\(.*\)\.read\(\)/
        $exec_call = "exec("

    condition:
        all of them and filesize < 10KB
}