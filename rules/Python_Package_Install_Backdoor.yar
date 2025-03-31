rule Python_Package_Install_Backdoor {
    meta:
        author = "RuleLLM"
        description = "Detects Python package installation backdoor using atexit and urllib"
        confidence = "90"
        severity = "80"
    
    strings:
        $atexit_register = "atexit.register"
        $urllib_request = "urllib.request.urlopen"
        $base64_encode = "base64.b64encode"
        $socket_fqdn = "socket.getfqdn"
        $setup_cmdclass = "cmdclass={'install':"
        $post_install = "_post_install"
    
    condition:
        all of them and
        filesize < 10KB
}