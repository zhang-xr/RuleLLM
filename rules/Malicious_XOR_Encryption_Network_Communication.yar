rule Malicious_XOR_Encryption_Network_Communication {
    meta:
        author = "RuleLLM"
        description = "Detects XOR encryption/decryption patterns used in network communication"
        confidence = 85
        severity = 80
    strings:
        $xor = /chr\(ord\([^\)]+\)\s*\^\s*ord\([^\)]+\)\)/
        $encryption_key = /encryption_key\s*=\s*'[^']+'/
        $requests_post = "requests.post"
        $server_url = /server_url\s*=\s*f"http:\/\/\{[^}]+\}:\{[^}]+\}"/
        $encrypted_data = /encrypted_data\s*=\s*xor_encrypt_decrypt\([^\)]+\)/
    condition:
        all of ($xor, $requests_post) and 
        any of ($encryption_key, $server_url, $encrypted_data) and 
        filesize < 100KB
}