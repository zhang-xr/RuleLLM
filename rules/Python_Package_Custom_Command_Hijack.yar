rule Python_Package_Custom_Command_Hijack {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that override install, develop, or egg_info commands with custom commands"
        confidence = 90
        severity = 85
    strings:
        $install = /class\s+\w+\(install\):/
        $develop = /class\s+\w+\(develop\):/
        $egg_info = /class\s+\w+\(egg_info\):/
        $run_method = /def\s+run\(self\):/
        $custom_call = /custom_command\(\)/
    condition:
        (1 of ($install, $develop, $egg_info)) and 
        $run_method and 
        $custom_call
}