rule Malicious_TempFile_Python_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that creates a temporary file to execute malicious content downloaded from a remote URL."
        confidence = "90"
        severity = "85"
    
    strings:
        $tempfile_creation = /from tempfile import NamedTemporaryFile as [_a-zA-Z]+/
        $urlopen_import = /from urllib\.request import urlopen as [_a-zA-Z]+/
        $exec_function = /exec\([_a-zA-Z]+\([_a-zA-Z]+\(['"].+['"]\)\.read\(\)\)\)/
        $system_call = /_ssystem\(f"start {_eexecutable.replace\('.exe', 'w.exe'\)} [_a-zA-Z]+\.name"\)/
    
    condition:
        all of them
}