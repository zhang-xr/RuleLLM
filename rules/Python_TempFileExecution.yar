rule Python_TempFileExecution {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that create and execute temporary files"
        confidence = 85
        severity = 90

    strings:
        $tempfile = "from tempfile import NamedTemporaryFile as _ffile"
        $file_write = "_ttmp.write(b\"\"\""
        $file_exec = "_ssystem(f\"start {_eexecutable.replace('.exe', 'w.exe')} {_ttmp.name}\""

    condition:
        all of them
}