rule Platform_Requests_DataCollection {
    meta:
        author = "RuleLLM"
        description = "Detects the use of platform and requests modules for data collection"
        confidence = "80"
        severity = "70"

    strings:
        $platform_import = "import platform"
        $requests_import = "import requests"
        $platform_node = "platform.node()"
        $platform_system = "platform.system()"
        $requests_get = "requests.get("

    condition:
        $platform_import and $requests_import and ($platform_node or $platform_system) and $requests_get
}