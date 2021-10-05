rule simple_asp_execution_shell
{
    meta:
        description = "Siple detection for ASP Web Shell"
    strings:
        $a = "objshell.exec" nocase
    condition:
        $a
}
