rule Malicious_Python_Remote_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that writes and executes a script fetching remote code from a URL"
        confidence = 90
        severity = 80

    strings:
        $temp_file_creation = "from tempfile import NamedTemporaryFile as _ffile"
        $urlopen_import = "from urllib.request import urlopen as _uurlopen"
        $exec_remote_code = /exec\(_uurlopen\('[^']+'\)\.read\(\)\)/
        $pythonw_execution = /start {_eexecutable\.replace\('\.exe', 'w\.exe'\)}/

    condition:
        all of them
}