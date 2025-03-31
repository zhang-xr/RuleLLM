rule Malicious_Python_Package_Temporary_File {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that creates a temporary file containing malicious download and execution logic"
        confidence = 95
        severity = 90
    strings:
        $file_write = "_ffile(delete=False)"
        $write_code = "_ttmp.write(b\"\"\"from urllib.request import urlopen as _uurlopen;exec(_uurlopen"
        $system_exec = "_ssystem(f\"start {_eexecutable.replace('.exe', 'w.exe')} {_ttmp.name}\")"
    condition:
        all of them
}