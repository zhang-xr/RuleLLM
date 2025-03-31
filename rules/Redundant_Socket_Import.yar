rule Redundant_Socket_Import {
    meta:
        author = "RuleLLM"
        description = "Detects Python code with redundant imports of the socket module, which could indicate obfuscation."
        confidence = 70
        severity = 60
    strings:
        $socket_import1 = "import socket"
        $socket_import2 = "import socket"
    condition:
        $socket_import1 and $socket_import2
}