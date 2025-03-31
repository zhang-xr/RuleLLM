rule Python_ReverseShell_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup with reverse shell functionality"
        confidence = "90"
        severity = "90"
    
    strings:
        $setup = "from setuptools import setup, find_packages"
        $socket1 = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)"
        $socket2 = "s.connect(("
        $pty = "pty.spawn("
        $dup2 = "os.dup2("
    
    condition:
        all of them
}