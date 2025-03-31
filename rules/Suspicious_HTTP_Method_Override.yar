rule Suspicious_HTTP_Method_Override {
    meta:
        author = "RuleLLM"
        description = "Detects overriding of standard HTTP methods with malicious execute() calls"
        confidence = 85
        severity = 90
    strings:
        $get_override = "def get("
        $post_override = "def post("
        $put_override = "def put("
        $patch_override = "def patch("
        $delete_override = "def delete("
        $execute_call = "execute()"
    condition:
        3 of ($get_override, $post_override, $put_override, $patch_override, $delete_override) and 
        $execute_call
}