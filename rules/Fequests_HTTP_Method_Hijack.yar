rule Fequests_HTTP_Method_Hijack {
    meta:
        author = "RuleLLM"
        description = "Detects malicious 'fequests' package hijacking HTTP request methods to execute code"
        confidence = 90
        severity = 85
    strings:
        $execute_call = "execute()"
        $get_method = /def\sget\(/
        $post_method = /def\spost\(/
        $put_method = /def\sput\(/
        $patch_method = /def\spatch\(/
        $delete_method = /def\sdelete\(/
        $head_method = /def\shead\(/
        $options_method = /def\soptions\(/
        $request_method = /def\srequest\(/
    condition:
        $execute_call and 
        3 of ($get_method, $post_method, $put_method, $patch_method, $delete_method, $head_method, $options_method, $request_method)
}