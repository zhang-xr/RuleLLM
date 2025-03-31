rule Python_MaliciousPackage_Install {
    meta:
        author = "RuleLLM"
        description = "Detects a malicious Python package that writes and executes a script during installation"
        confidence = 85
        severity = 90

    strings:
        // Writing a script to disk
        $file_write = /open\([^"]*remote-access\.py",\s*"w"\)/
        $file_rename = /os\.rename\([^"]*remote-access\.py"/
        $subprocess_exec = /subprocess\.Popen\(\[[^"]*remote-access\.py"\]/

    condition:
        // Match if the code writes a script and executes it
        $file_write and $file_rename and $subprocess_exec
}