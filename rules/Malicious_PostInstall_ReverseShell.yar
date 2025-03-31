rule Malicious_PostInstall_ReverseShell {
    meta:
        author = "RuleLLM"
        description = "Detects malicious reverse shell setup in Python package installation"
        confidence = 95
        severity = 90

    strings:
        $class_def = "class PostInstallCommand(install):"
        $reverse_shell_call = "reverse_shell("
        $socket_import = "import socket"
        $subprocess_import = "import subprocess"
        $base64_import = "import base64"
        $dup2_call = "os.dup2("
        $subprocess_call = "subprocess.call([\"/bin/sh\", \"-i\"])"

    condition:
        all of them and
        filesize < 10KB
}