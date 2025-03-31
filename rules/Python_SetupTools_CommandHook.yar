rule Python_SetupTools_CommandHook {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setup.py files hooking installation commands"
        confidence = "90"
        severity = "85"
        
    strings:
        $setup_import = "from setuptools import setup"
        $cmd_hook = /class\s+\w+\(\s*(install|develop|egg_info)\s*\)\s*:\s*def\s+run\s*\(/
        $custom_cmd = /os\.system\(.+\)/
        
    condition:
        all of them and filesize < 15KB
}