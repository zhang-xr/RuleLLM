rule Plugin_Manager_Suspicious {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious plugin manager implementation often used in malicious code"
        confidence = "85"
        severity = "80"
    strings:
        $plugin_manager = "PluginManager"
        $register_plugin = "register_plugin"
        $plugin_types = /OUTLIER_DETECTION|SERVER_CONNECTOR|SERVICE_ROUTER|LOAD_BALANCE|CIRCUIT_BREAKER|LOCAL_CACHE|STAT_REPORTER/
        $default_manager = "DefaultPluginManager"
    condition:
        all of ($plugin_manager, $register_plugin, $default_manager) and 3 of ($plugin_types)
}