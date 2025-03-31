rule Python_Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects potential data exfiltration patterns in Python code"
        confidence = 88
        severity = 90
    strings:
        $socket_import = "import socket"
        $encode_call = /\.encode\([\"']utf-8[\"']\)/
        $send_call = /\.sendall\(/
        $connect_call = /\.connect\(/
    condition:
        all of them and 
        not filesize < 1KB and 
        not $socket_import in (0..filesize-100)
}