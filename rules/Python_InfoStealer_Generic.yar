rule Python_InfoStealer_Generic {
    meta:
        author = "RuleLLM"
        description = "Generic detection for Python-based information stealers"
        confidence = 80
        severity = 70
    strings:
        $os_module = "import os" ascii wide
        $urllib_module = /from urllib\.(request|error|parse)/ ascii wide
        $datetime_module = "from datetime import datetime" ascii wide
        $system_info = /(hostname|publicIP|homeDirectory|currentDirectory)/ ascii wide
    condition:
        all of ($os_module, $urllib_module, $datetime_module) and
        any of ($system_info)
}