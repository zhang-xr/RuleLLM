rule Suspicious_PluginFramework {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious plugin framework implementation that could be used for malicious purposes"
        confidence = "80"
        severity = "70"
    
    strings:
        $plugin_manager = "PluginManager"
        $plugin_container = "plugin_container"
        $plugin_instance = "plugin_instance"
        $register_plugin = "register_plugin"
        $get_plugin = "get_plugin"
    
    condition:
        3 of them and 
        filesize < 100KB
}