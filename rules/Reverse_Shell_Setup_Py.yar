rule Reverse_Shell_Setup_Py {
    meta:
        author = "RuleLLM"
        description = "Detects reverse shell behavior in Python setup.py scripts"
        confidence = 90
        severity = 95

    strings:
        $dup2 = "os.dup2"
        $subprocess_call = "subprocess.call"
        $bin_sh = "/bin/sh"
        $socket_connect = "s.connect"
        $base64_decode = "base64.b64decode"

    condition:
        all of ($dup2, $subprocess_call, $bin_sh, $socket_connect) and
        any of ($base64_decode)
}