rule Python_Remote_Code_Fetch {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that fetches and executes remote code using urllib.request.urlopen"
        confidence = 95
        severity = 85

    strings:
        $urlopen_import = "from urllib.request import urlopen as _uurlopen"
        $exec_remote_code = /exec\(_uurlopen\('[^']+'\)\.read\(\)\)/

    condition:
        all of them
}