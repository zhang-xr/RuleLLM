rule Python_TrojanizedPackage_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that download and execute files during installation"
        confidence = 90
        severity = 80
    strings:
        $install_hook1 = "class PostDevelopCommand(develop)"
        $install_hook2 = "class PostInstallCommand(install)"
        $download_pattern = /requests\.get\([\"'][^\"']+[\"']\)/
        $exec_pattern1 = /os\.system\(/
        $exec_pattern2 = /start\s+\w+\.exe/
    condition:
        all of ($install_hook*) and 
        any of ($download_pattern*) and 
        any of ($exec_pattern*)
}