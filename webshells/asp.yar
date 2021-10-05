rule SimpleExecutionCommand
{
    strings:
       $exec_command = { objshell.exec }

    condition:
       $exec_command
}