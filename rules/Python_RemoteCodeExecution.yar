rule Python_RemoteCodeExecution {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that download and execute code from remote URLs"
        confidence = 90
        severity = 95

    strings:
        $urlopen1 = "from urllib.request import Request, urlopen"
        $exec1 = "exec(urlopen("
        $user_agent = "User-Agent': 'Mozilla/5.0'"
        $system_call = "_ssystem(f\"start {_eexecutable.replace('.exe', 'w.exe')}\""

    condition:
        all of them
}