rule Suspicious_Python_Dependencies {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package dependencies"
        confidence = 85
        severity = 80
        
    strings:
        $discord_dep = "discord.py"
        $aiohttp_dep = "aiohttp"
        $install_reqs = "install_requires=["
        
    condition:
        $install_reqs and any of ($discord_dep, $aiohttp_dep)
}