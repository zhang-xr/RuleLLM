rule Malicious_Executable_Download_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects download and execution of a potentially malicious executable from a remote server."
        confidence = 95
        severity = 95

    strings:
        $url_pattern = /https:\/\/cdn\.discordapp\.com\/attachments\/\d+\/\d+\/[^\/]+\.exe/
        $requests_import = "import requests"
        $tempfile_import = "import tempfile"
        $subprocess_import = "import subprocess"
        $requests_get = "requests.get("
        $tempfile_namedtemporaryfile = "tempfile.NamedTemporaryFile("
        $subprocess_call = "subprocess.call(["

    condition:
        all of them
}