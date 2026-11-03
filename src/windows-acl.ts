import { execFileSync } from 'node:child_process'

export type WindowsAcl = (path: string, action: 'check' | 'verify' | 'restrict', directory: boolean) => void

export const windowsAcl: WindowsAcl = (path, action, directory) => {
  const script = `$ErrorActionPreference='Stop'; $p=$env:SHODAN_AXI_ACL_PATH; $item=Get-Item -LiteralPath $p -Force; `
    + `if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point' }; `
    + `$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User; $allowed=@($sid.Value,'S-1-5-18','S-1-5-32-544'); `
    + (action === 'check' ? '' : action === 'restrict'
      ? `$acl=New-Object Security.AccessControl.${directory ? 'DirectorySecurity' : 'FileSecurity'}; $acl.SetOwner($sid); $acl.SetAccessRuleProtection($true,$false); `
        + `foreach ($s in $allowed) { $id=New-Object Security.Principal.SecurityIdentifier($s); $rule=New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','${directory ? 'ContainerInherit,ObjectInherit' : 'None'}','None','Allow'); $acl.AddAccessRule($rule) }; Set-Acl -LiteralPath $p -AclObject $acl`
      : `$acl=Get-Acl -LiteralPath $p; if (!$acl.AreAccessRulesProtected -or ($acl.Owner -ne $sid.Translate([Security.Principal.NTAccount]).Value -and $acl.Owner -ne $sid.Value)) { throw 'Unprotected ACL' }; `
        + `foreach ($r in $acl.Access) { $s=$r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value; if ($r.IsInherited -or ($r.AccessControlType -eq 'Allow' -and $s -notin $allowed)) { throw 'Unexpected ACL' } }`)
  execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { env: { ...process.env, SHODAN_AXI_ACL_PATH: path }, stdio: 'pipe' })
}
