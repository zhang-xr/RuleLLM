rule Suspicious_Python_PluginFramework {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious plugin management framework that could be used for malicious purposes"
        confidence = "85"
        severity = "75"
    
    strings:
        $plugin_manager = "PluginManager"
        $plugin_type = "PluginType"
        $instance_management = /(get|set)_instance\(/
        $plugin_registration = /register_plugin\(/
        $event_handling = /register_event_handle\(/
    
    condition:
        3 of them and filesize < 15KB
}