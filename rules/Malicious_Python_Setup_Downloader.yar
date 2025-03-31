rule Malicious_Python_Setup_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup scripts that download and execute external binaries"
        confidence = 90
        severity = 80
    strings:
        $setup_import = "from setuptools import setup, find_packages"
        $custom_install = "class InstallCommand(install)"
        $download_pattern = "requests.get(url)"
        $exec_pattern = "subprocess.Popen([binary_path]"
        $xor_pattern = "for b, k in zip(buf, function1)"
        $path_pattern = "/Library/Application Support"
    condition:
        all of them and 
        filesize < 10KB
}