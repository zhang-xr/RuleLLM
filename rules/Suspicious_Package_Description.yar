rule Suspicious_Package_Description {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious package description text commonly used in dependency confusion attacks"
        confidence = 85
        severity = 70
    strings:
        $desc1 = "This package is a proof of concept"
        $desc2 = "used by author to conduct research"
        $desc3 = "It has been uploaded for test purposes only"
        $desc4 = "The code is not malicious in any way"
    condition:
        3 of them and
        filesize < 10KB
}