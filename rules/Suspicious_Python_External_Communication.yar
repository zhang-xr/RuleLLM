rule Suspicious_Python_External_Communication {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that communicates with external servers while collecting system information"
        confidence = 85
        severity = 75
    strings:
        $requests = "import requests"
        $getpass = "import getpass"
        $socket = "import socket"
        $os = "import os"
        $post = "requests.post("
    condition:
        all of them
}