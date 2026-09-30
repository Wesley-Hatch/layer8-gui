"""
Reusable PowerShell snippets shared by several checks.

PS_ACL_HELPER defines two functions the privilege-escalation checks prepend to
their scripts:

  Get-RiskyAcl <path>     -> string of risky filesystem ACEs, or $null
  Get-RiskyRegAcl <path>  -> string of risky registry ACEs, or $null

"Risky" = an Allow ACE granting write/modify-class rights to a low-privileged
principal (Everyone, Users, Authenticated Users, INTERACTIVE). That is the exact
condition that turns a SYSTEM service binary / registry key / PATH directory into
a local privilege-escalation primitive.
"""

PS_ACL_HELPER = r"""
$RiskyIds=@('Everyone','BUILTIN\Users','NT AUTHORITY\Authenticated Users','NT AUTHORITY\INTERACTIVE','BUILTIN\Everyone');
function Get-RiskyAcl($p){
  if([string]::IsNullOrWhiteSpace($p)){return $null}
  if(-not (Test-Path -LiteralPath $p)){return $null}
  try{$acl=Get-Acl -LiteralPath $p}catch{return $null}
  $wr='Write|Modify|FullControl|CreateFiles|WriteData|AppendData|CreateDirectories|ChangePermissions|TakeOwnership';
  $hits=@();
  foreach($ace in $acl.Access){
    if($ace.AccessControlType -ne 'Allow'){continue}
    $id=[string]$ace.IdentityReference.Value;
    if(($RiskyIds -contains $id) -and ($ace.FileSystemRights.ToString() -match $wr)){$hits+="$id=$($ace.FileSystemRights)"}
  }
  if($hits.Count){return ($hits -join '; ')} else {return $null}
}
function Get-RiskyRegAcl($p){
  if(-not (Test-Path -LiteralPath $p)){return $null}
  try{$acl=Get-Acl -LiteralPath $p}catch{return $null}
  $wr='SetValue|WriteKey|CreateSubKey|FullControl|ChangePermissions|TakeOwnership';
  $hits=@();
  foreach($ace in $acl.Access){
    if($ace.AccessControlType -ne 'Allow'){continue}
    $id=[string]$ace.IdentityReference.Value;
    if(($RiskyIds -contains $id) -and ($ace.RegistryRights.ToString() -match $wr)){$hits+="$id=$($ace.RegistryRights)"}
  }
  if($hits.Count){return ($hits -join '; ')} else {return $null}
}
function Get-ServiceExe($pathName){
  if([string]::IsNullOrWhiteSpace($pathName)){return $null}
  $pn=$pathName.Trim();
  if($pn -match '^"([^"]+)"'){return $matches[1]}
  $m=[regex]::Match($pn,'^(.*?\.exe)','IgnoreCase');
  if($m.Success){return $m.Groups[1].Value}
  $sp=$pn.Split(' ')[0];
  return $sp
}
"""
