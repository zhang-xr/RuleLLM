rule Remote_Code_Execution_via_Exec {
    meta:
        author = "RuleLLM"
        description = "Detects the use of exec to execute code fetched from a remote URL"
        confidence = 95
        severity = 90

    strings:
        $urlopen_import = "from urllib.request import urlopen"
        $exec_pattern = /exec\(.*urlopen\(.*\)\.read\(\)\)/

    condition:
        $urlopen_import and $exec_pattern
}