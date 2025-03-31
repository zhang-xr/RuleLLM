rule Malicious_Python_Package_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects a malicious Python package that downloads and executes a binary from a remote server."
        confidence = 90
        severity = 90
    
    strings:
        $setup_import = "from setuptools import setup, find_packages"
        $requests_import = "import requests"
        $subprocess_import = "import subprocess"
        $custom_run = "def CustomRun"
        $function_gen = "def function_gen"
        $xor_pattern = /chr\(b \^ k\)/
        $binary_path = "~/.local/bin"
        $install_command = "class InstallCommand(install)"
        $setup_call = "setup("
    
    condition:
        all of ($setup_import, $requests_import, $subprocess_import) and 
        (any of ($custom_run, $function_gen)) and 
        (any of ($xor_pattern, $binary_path)) and 
        (all of ($install_command, $setup_call))
}