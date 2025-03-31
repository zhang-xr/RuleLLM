rule Suspicious_Python_Plugin_System {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious plugin management system in Python code"
        confidence = "85"
        severity = "75"
    
    strings:
        $plugin_manager = "PluginManager"
        $register_plugin = "register_plugin"
        $event_handling = "event_handle_map"
        $instance_management = "get_instance"
    
    condition:
        3 of them and filesize < 100KB
}