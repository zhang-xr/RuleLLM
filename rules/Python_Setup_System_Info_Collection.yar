rule Python_Setup_System_Info_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects system information collection in Python setup scripts"
        confidence = 85
        severity = 75
    strings:
        $platform_node = "platform.node()"
        $platform_system = "platform.system()"
        $requests_get = "requests.get("
        $json_access = /\.json\(\)\[['"][^\]]+['"]\]/
    condition:
        3 of them and filesize < 10KB
}