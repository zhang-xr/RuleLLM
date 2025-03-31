rule Suspicious_System_Binary_Installer {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious binary installation patterns in Python scripts"
        confidence = 95
        severity = 90
    strings:
        $local_bin = "os.path.expanduser('~/.local/bin')"
        $chmod = "os.chmod(binary_path, stat.S_IREAD | stat.S_IEXEC"
        $binary_write = "with open(binary_path, 'wb') as f"
        $exec_pattern = "subprocess.Popen([binary_path]"
    condition:
        3 of them and 
        filesize < 20KB
}