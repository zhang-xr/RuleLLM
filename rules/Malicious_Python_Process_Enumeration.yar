rule Malicious_Python_Process_Enumeration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code enumerating process information"
        confidence = 85
        severity = 80
    strings:
        $proc_access1 = /\/proc\/[^\/]+\/status/
        $proc_access2 = /\/proc\/[^\/]+\/cwd/
        $ppid_check = "PPid"
        $os_readlink = "os.readlink"
    condition:
        all of them and filesize < 10KB
}