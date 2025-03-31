rule Python_Persistence_FileWrite_Execute {
    meta:
        author = "RuleLLM"
        description = "Detects Python malware writing to a file and executing it"
        confidence = 85
        severity = 90

    strings:
        $file_write = "open(\"remote-access.py\", \"w\")"
        $file_close = ".close()"
        $os_rename = "os.rename"
        $subprocess_popen = "subprocess.Popen"
        $python_exec = "python3"

    condition:
        all of ($file_write, $file_close, $os_rename) and
        $subprocess_popen and
        $python_exec
}