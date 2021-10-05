rule SimpleExecutionCommand
{
    strings:
       $exec_command = "objshell.exec" nocase

    condition:
       $exec_command
}