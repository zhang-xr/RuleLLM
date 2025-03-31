rule Python_PostInstall_ReverseShell {
    meta:
        author = "RuleLLM"
        description = "Detects Python package setup with post-install reverse shell"
        confidence = 90
        severity = 95

    strings:
        $post_install = "class PostInstallCommand(install)"
        $reverse_shell = "def reverse_shell(host, port):"
        $base64_decode = "base64.b64decode"
        $socket_connect = "s.connect"
        $subprocess_call = "subprocess.call([\"/bin/sh\", \"-i\"])"

    condition:
        all of them
}