rule Python_Custom_Install_Command {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with custom install commands that may execute malicious code"
        confidence = 85
        severity = 75

    strings:
        $custom_install = "cmdclass={'install':"
        $install_requires = "install_requires=["
        $discord_py = "discord.py"
        $aiohttp = "aiohttp"
        $requests = "requests"

    condition:
        $custom_install and
        ($install_requires or 2 of ($discord_py, $aiohttp, $requests))
}