rule Suspicious_PowerShell_EncodedCommand {
  strings:
    $a = "-enc" ascii nocase
    $b = "-encodedcommand" ascii nocase
  condition:
    1 of them
}

rule Suspicious_Credential_Keywords {
  strings:
    $a = "mimikatz" ascii nocase
    $b = "sekurlsa" ascii nocase
    $c = "lsadump" ascii nocase
  condition:
    1 of them
}
