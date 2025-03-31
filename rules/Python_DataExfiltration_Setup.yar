rule Python_DataExfiltration_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files that collect and exfiltrate system data during installation"
        confidence = 90
        severity = 80
    strings:
        $install_class = "class Analytics(install):"
        $subprocess_call = "subprocess.call([sys.executable"
        $requests_post = "requests.post("
        $cmdclass = "'install': Analytics"
        $platform = "platform.system()"
        $psutil = "psutil.boot_time()"
        $socket = "socket.gethostname()"
    condition:
        all of ($install_class, $cmdclass) and 
        3 of ($subprocess_call, $requests_post, $platform, $psutil, $socket)
}