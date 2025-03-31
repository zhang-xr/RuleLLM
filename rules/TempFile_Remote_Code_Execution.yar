rule TempFile_Remote_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects the combination of temporary file creation and remote code execution"
        confidence = 92
        severity = 85

    strings:
        $tempfile_creation = "from tempfile import NamedTemporaryFile"
        $urlopen_usage = "from urllib.request import urlopen"
        $exec_usage = /exec\(.*urlopen\(.*\)\.read\(\)\)/

    condition:
        $tempfile_creation and $urlopen_usage and $exec_usage
}