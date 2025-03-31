rule Suspicious_Python_Dependencies {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with suspicious dependencies like gitpython and discord.py"
        confidence = 80
        severity = 75

    strings:
        $gitpython = "gitpython" nocase
        $discordpy = "discord.py" nocase
        $aiohttp = "aiohttp" nocase
        $install_requires = "install_requires=[" nocase

    condition:
        all of ($gitpython, $discordpy, $aiohttp) and
        $install_requires and
        filesize < 10KB
}