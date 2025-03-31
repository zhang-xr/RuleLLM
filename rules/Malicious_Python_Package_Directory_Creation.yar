rule Malicious_Python_Package_Directory_Creation {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that creates suspicious directories and files."
        confidence = 80
        severity = 85

    strings:
        $os_mkdir = "os.mkdir("
        $open_write = "open(..., 'a').write("
        $subprocess_run = "subprocess.run("

    condition:
        all of them and filesize < 10KB
}