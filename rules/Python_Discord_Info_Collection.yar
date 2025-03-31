rule Python_Discord_Info_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Discord info collection function"
        confidence = 85
        severity = 80
    strings:
        $discord_func = "send_discord_info" ascii wide
        $os_import = "import os" ascii wide
        $requests_import = "import requests" ascii wide
        $path_join = "os.path.join" ascii wide
    condition:
        all of them
}