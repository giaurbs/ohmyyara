rule trivial_asp_shell {
    meta:
        description = "Trivial check for ASP Shell"

    strings:
        $shell_exec = "objshell.exec"

    condition:
        all of them
}
