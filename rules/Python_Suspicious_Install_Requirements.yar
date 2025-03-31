rule Python_Suspicious_Install_Requirements {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package installation requirements"
        confidence = 80
        severity = 70
    strings:
        $discord_py = "discord.py" ascii wide
        $aiohttp = "aiohttp" ascii wide
        $socket_req = /["']sockets?["']/ ascii wide
        $install_req = "install_requires=" ascii wide
    condition:
        all of ($discord_py, $aiohttp) and any of ($socket_req, $install_req)
}