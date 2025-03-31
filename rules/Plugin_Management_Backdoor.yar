rule Plugin_Management_Backdoor {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious plugin management system that could be used as a backdoor"
        confidence = "80"
        severity = "75"
    strings:
        $plugin_manager = "PluginManager"
        $register_method = "register("
        $get_instance = "get_instance("
    condition:
        all of them
}