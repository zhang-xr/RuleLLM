rule python_reverse_shell {
    meta:
        author = "RuleLLM"
        description = "Detects Python reverse shell behavior with Base64-encoded IP and port"
        confidence = 90
        severity = 95

    strings:
        $base64_ip = "NDkuMjMzLjEyMS41Mw=="  // Base64-encoded IP
        $base64_port = "NTQ="                // Base64-encoded port
        $dup2_call = "os.dup2"               // Used to redirect streams
        $subprocess_call = "subprocess.call" // Used to execute shell
        $socket_connect = "s.connect"        // Socket connection
        $reverse_shell = "/bin/sh"           // Shell invocation

    condition:
        all of ($base64_ip, $base64_port, $dup2_call, $subprocess_call, $socket_connect, $reverse_shell)
}