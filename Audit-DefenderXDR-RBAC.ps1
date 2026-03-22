# Audit-DefenderXDR-RBAC.ps1 v2.0.0
# Compativel com PowerShell 5.1+ e PowerShell 7+
# Modulos necessarios: Microsoft.Graph (Install-Module Microsoft.Graph -Scope CurrentUser)
<#
.SYNOPSIS
    Auditoria estado-da-arte de RBAC do Microsoft Defender XDR. Gera relatorio HTML interativo.
.DESCRIPTION
    Mapeia Unified RBAC (custom roles, assignments, permission categories), Entra ID Roles,
    grupos, workloads. Classifica risco por principal. Executa KQL no Advanced Hunting.
    Gera relatorio HTML com SVG, graficos, matriz de permissoes, recomendacoes CIS/NIST.
.PARAMETER OutputPath
    Caminho de saida. Default: pasta atual.
.PARAMETER DaysBack
    Dias de historico para KQL. Default: 30.
.NOTES
    Permissoes Graph: Directory.Read.All, RoleManagement.Read.All, ThreatHunting.Read.All
    Desenvolvido por Rafael Franca - ODEFENDER | github.com/rfranca777
    v2.0.0 - State of the Art RBAC Audit
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [int]$DaysBack = 30
)
$ErrorActionPreference = "Stop"
$scriptVersion = "2.1.0"

# =====================================================================
# FUNCOES AUXILIARES
# =====================================================================
function Write-Step($M) { Write-Host "`n[$((Get-Date).ToString('HH:mm:ss'))] $M" -ForegroundColor Cyan }
function Write-OK($M) { Write-Host "  [OK] $M" -ForegroundColor Green }
function Write-Warn($M) { Write-Host "  [!] $M" -ForegroundColor Yellow }
function Invoke-KQL($Q) { (Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" -Body (@{Query=$Q} | ConvertTo-Json -Depth 5)).results }
function Mask($Id) { if ($Id.Length -gt 12) { "$($Id.Substring(0,8))...$($Id.Substring($Id.Length-4))" } else { $Id } }
function HtmlEncode($S) { if ($null -eq $S) { return "" }; $S -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }

# Mapeamento de nivel de risco
function Get-RiskInfo {
    param([string]$Role, [string]$Permissions)
    if ($Role -match "Global Administrator") { return @{Level="CRITICAL";Score=100;Color="#f85149";Icon="&#x1F534;"} }
    if ($Role -match "Security Administrator") { return @{Level="HIGH";Score=80;Color="#ff7b72";Icon="&#x1F7E0;"} }
    if ($Permissions -match "manage" -and $Permissions -match "secops") { return @{Level="HIGH";Score=75;Color="#ff7b72";Icon="&#x1F7E0;"} }
    if ($Role -match "Security Operator") { return @{Level="MEDIUM";Score=50;Color="#d29922";Icon="&#x1F7E1;"} }
    if ($Permissions -match "manage") { return @{Level="MEDIUM";Score=45;Color="#ffa657";Icon="&#x1F7E1;"} }
    if ($Role -match "Security Reader|Global Reader") { return @{Level="LOW";Score=20;Color="#3fb950";Icon="&#x1F7E2;"} }
    if ($Permissions -match "read") { return @{Level="LOW";Score=15;Color="#3fb950";Icon="&#x1F7E2;"} }
    return @{Level="INFO";Score=10;Color="#8b949e";Icon="&#x26AA;"}
}

# =====================================================================
# 1. VALIDACAO DE MODULOS
# =====================================================================
Write-Step "Validando modulos..."
$requiredModules = @("Microsoft.Graph.Authentication","Microsoft.Graph.Identity.DirectoryManagement","Microsoft.Graph.Identity.Governance","Microsoft.Graph.Groups","Microsoft.Graph.DirectoryObjects","Microsoft.Graph.Security")
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue)) {
        Write-Host "[!] Modulo $mod nao encontrado. Instalando..." -ForegroundColor Yellow
        try {
            Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck -ErrorAction Stop
            Write-Host "  [OK] $mod instalado." -ForegroundColor Green
        } catch {
            Write-Host "[ERRO] Falha ao instalar $mod : $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Execute manualmente: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
            exit 1
        }
    }
    Import-Module $mod -ErrorAction SilentlyContinue
}

$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportFile = Join-Path $OutputPath "DefenderXDR-RBAC-Audit_$ts.html"

# Roles Entra ID que concedem acesso ao Defender XDR (documentadas em manage-rbac)
$secRoles = @("Global Administrator","Global Reader","Security Administrator","Security Operator","Security Reader","Compliance Administrator","Compliance Data Administrator")

# URLs do portal Defender XDR (verificadas)
$portal = @{
    Perms      = "https://security.microsoft.com/securitysettings/mtp_roles"
    Hunt       = "https://security.microsoft.com/v2/advanced-hunting"
    Audit      = "https://security.microsoft.com/auditlogsearch"
    Incidents  = "https://security.microsoft.com/incidents"
    SecScore   = "https://security.microsoft.com/securescore"
    Entra      = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AllRoles"
    PIM        = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PrivilegedIdentityManagement.ReactV3/~/quickStart"
    AccessRev  = "https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/Controls"
    MDE        = "https://security.microsoft.com/machines"
    MDO        = "https://security.microsoft.com/threatexplorer"
    MDI        = "https://security.microsoft.com/identities"
    MDCA       = "https://security.microsoft.com/cloudapps/dashboard"
}

# =====================================================================
# 2. AUTENTICACAO
# =====================================================================
Write-Step "Autenticacao..."
$scopes = @("Directory.Read.All","RoleManagement.Read.All","ThreatHunting.Read.All")
$ctx = Get-MgContext
if (-not $ctx) {
    Connect-MgGraph -Scopes ($scopes -join ",") -UseDeviceCode -NoWelcome
    $ctx = Get-MgContext
}
$miss = $scopes | Where-Object { $_ -notin $ctx.Scopes }
if ($miss.Count -gt 0) {
    Write-Warn "Scopes ausentes: $($miss -join ', '). Reconectando..."
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Connect-MgGraph -Scopes ($scopes -join ",") -UseDeviceCode -NoWelcome
    $ctx = Get-MgContext
}
Write-OK "$($ctx.Account) | Tenant: $(Mask $ctx.TenantId)"

# =====================================================================
# 3. WORKLOADS ATIVOS
# =====================================================================
Write-Step "Detectando workloads..."
$wl = @(
    @{N="MDE"; F="Defender for Endpoint"; T="DeviceInfo"; C="#4fc3f7"; U=$portal.MDE},
    @{N="MDO"; F="Defender for Office 365"; T="EmailEvents"; C="#81c784"; U=$portal.MDO},
    @{N="MDI"; F="Defender for Identity"; T="IdentityDirectoryEvents"; C="#ffb74d"; U=$portal.MDI},
    @{N="MDCA"; F="Defender for Cloud Apps"; T="CloudAppEvents"; C="#ce93d8"; U=$portal.MDCA}
)
foreach ($w in $wl) {
    try { $r = Invoke-KQL "$($w.T) | take 1"; $w.A = ($r.Count -gt 0) }
    catch { $w.A = $false }
    $statusTxt = if ($w.A) { "Ativo" } else { "Sem dados" }
    Write-OK "$($w.N): $statusTxt"
}
$aWL = ($wl | Where-Object { $_.A }).Count

# =====================================================================
# 4. ENTRA ID ROLES + PRINCIPALS
# =====================================================================
Write-Step "Entra ID Roles..."
$rd = @()
$allDefs = Get-MgRoleManagementDirectoryRoleDefinition -All
$allAsgn = Get-MgRoleManagementDirectoryRoleAssignment -All
foreach ($rn in $secRoles) {
    $def = $allDefs | Where-Object { $_.DisplayName -eq $rn }
    if (-not $def) { continue }
    $asgn = $allAsgn | Where-Object { $_.RoleDefinitionId -eq $def.Id }
    if ($asgn.Count -eq 0) {
        $rd += [PSCustomObject]@{Role=$rn;Typ="-";Name="(vazio)";Id="-";FullId="-"}
        Write-OK "$rn : vazio"
    } else {
        foreach ($a in $asgn) {
            try {
                $p = Get-MgDirectoryObject -DirectoryObjectId $a.PrincipalId -ErrorAction Stop
                $t = $p.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''
                $n = $p.AdditionalProperties.displayName
            } catch { $t = "?"; $n = $a.PrincipalId }
            $rd += [PSCustomObject]@{Role=$rn;Typ=$t;Name=$n;Id=Mask $a.PrincipalId;FullId=$a.PrincipalId}
            Write-OK "$rn : [$t] $n"
        }
    }
}
$nU = ($rd | Where-Object { $_.Typ -eq 'user' -and $_.Name -ne '(vazio)' }).Count
$nG = ($rd | Where-Object { $_.Typ -eq 'group' }).Count
$nS = ($rd | Where-Object { $_.Typ -eq 'servicePrincipal' }).Count

# =====================================================================
# 5. DEFENDER UNIFIED RBAC (custom roles + assignments)
# =====================================================================
Write-Step "Defender Unified RBAC..."
$rb = @()
$dGrp = [System.Collections.Generic.HashSet[string]]::new()
$dR = @{value=@()}
$dA = @{value=@()}
try {
    $dR = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/roleManagement/defender/roleDefinitions" -ErrorAction Stop
    $dA = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/roleManagement/defender/roleAssignments" -ErrorAction Stop
    foreach ($role in $dR.value) {
        $pm = ($role.rolePermissions | ForEach-Object { $_.allowedResourceActions }) -join ", "
        $as = $dA.value | Where-Object { $_.roleDefinitionId -eq $role.id }
        if ($as.Count -eq 0) {
            $rb += [PSCustomObject]@{CR=$role.displayName;Pm=$pm;To="(vazio)";TT="-";Mb="-";Scope="-";RoleId=$role.id}
        } else {
            foreach ($a in $as) {
                foreach ($principalId in $a.principalIds) {
                    try {
                        $o = Get-MgDirectoryObject -DirectoryObjectId $principalId -ErrorAction Stop
                        $ot = $o.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''
                        $on = $o.AdditionalProperties.displayName
                        $ml = "-"
                        if ($ot -eq 'group') {
                            [void]$dGrp.Add($on)
                            $ms = Get-MgGroupMember -GroupId $principalId -ErrorAction SilentlyContinue
                            $ml = ($ms | ForEach-Object { $_.AdditionalProperties.displayName }) -join ", "
                            if (-not $ml) { $ml = "(vazio)" }
                        }
                        $scope3 = if ($a.appScopeIds -contains "/") { "Global (todos workloads)" } else { ($a.appScopeIds -join ",") }
                        $rb += [PSCustomObject]@{CR=$role.displayName;Pm=$pm;To=$on;TT=$ot;Mb=$ml;Scope=$scope3;RoleId=$role.id}
                        Write-OK "'$($role.displayName)' -> [$ot] $on"
                    } catch { Write-Warn "Erro ao resolver $principalId" }
                }
            }
        }
    }
} catch {
    Write-Warn "RBAC: $($_.Exception.Message)"
    $rb += [PSCustomObject]@{CR="(indisponivel)";Pm="-";To="-";TT="-";Mb="-";Scope="-";RoleId="-"}
}

# =====================================================================
# 6. MATRIZ DE PERMISSOES POR CATEGORIA
# =====================================================================
Write-Step "Mapeando categorias de permissao..."
$permCatDefs = @(
    @{Key="secops";        Name="Security Operations"; Desc="Incidents, alerts, response actions, live response, hunting"; Color="#f85149"; Icon="&#x1F6E1;&#xFE0F;"}
    @{Key="securityposture"; Name="Security Posture";    Desc="Vulnerability mgmt, baselines, Secure Score, exposure"; Color="#d29922"; Icon="&#x1F4CA;"}
    @{Key="authorization";  Name="Authorization/Settings"; Desc="Role mgmt, system settings, detection tuning"; Color="#58a6ff"; Icon="&#x2699;&#xFE0F;"}
    @{Key="dataops";        Name="Data Operations";     Desc="Data retention, Sentinel data lake, analytics jobs"; Color="#3fb950"; Icon="&#x1F4BE;"}
)

$permMatrix = @()
foreach ($role in $dR.value) {
    $actions = @()
    foreach ($rp in $role.rolePermissions) { $actions += $rp.allowedResourceActions }
    $row = @{RoleName=$role.displayName; Cats=@{}}
    foreach ($cat in $permCatDefs) {
        $catActions = $actions | Where-Object { $_ -match $cat.Key }
        $hasManage = ($catActions | Where-Object { $_ -match 'manage' }).Count -gt 0
        $hasRead = ($catActions | Where-Object { $_ -match 'read' }).Count -gt 0
        $level = if ($hasManage) { "manage" } elseif ($hasRead) { "read" } else { "-" }
        $row.Cats[$cat.Key] = $level
    }
    $permMatrix += $row
}
Write-OK "$($permMatrix.Count) roles mapeadas em 4 categorias"

# =====================================================================
# 7. CAMINHOS DE ACESSO + CLASSIFICACAO DE RISCO
# =====================================================================
Write-Step "Mapeando caminhos de acesso e risco..."
$accessPaths = @()

# Entra ID Roles diretas
foreach ($entry in $rd) {
    if ($entry.Name -eq "(vazio)") { continue }
    $riskInfo = Get-RiskInfo -Role $entry.Role -Permissions ""
    $accessPaths += [PSCustomObject]@{
        Principal=$entry.Name; PType=$entry.Typ; Level=$riskInfo.Level; Score=$riskInfo.Score
        LevelColor=$riskInfo.Color; LevelIcon=$riskInfo.Icon
        Role=$entry.Role; Path="Entra ID Role (direto)"; Group="-"; Permissions=""
    }
}

# RBAC via grupo
foreach ($rbEntry in $rb) {
    if ($rbEntry.To -eq "(vazio)" -or $rbEntry.To -eq "(indisponivel)") { continue }
    $permShort = ($rbEntry.Pm -replace 'microsoft\.xdr/','') -replace '/\*/manage',''
    if ($rbEntry.TT -eq "group" -and $rbEntry.Mb -and $rbEntry.Mb -ne "-" -and $rbEntry.Mb -ne "(vazio)") {
        foreach ($memberName in ($rbEntry.Mb -split ",")) {
            $mn = $memberName.Trim()
            if ($mn) {
                $riskInfo = Get-RiskInfo -Role "RBAC: $($rbEntry.CR)" -Permissions $rbEntry.Pm
                $accessPaths += [PSCustomObject]@{
                    Principal=$mn; PType="user (via grupo)"; Level=$riskInfo.Level; Score=$riskInfo.Score
                    LevelColor=$riskInfo.Color; LevelIcon=$riskInfo.Icon
                    Role="RBAC: $($rbEntry.CR)"; Path="Grupo -> RBAC Role"; Group=$rbEntry.To; Permissions=$permShort
                }
            }
        }
    } elseif ($rbEntry.TT -eq "user") {
        $riskInfo = Get-RiskInfo -Role "RBAC: $($rbEntry.CR)" -Permissions $rbEntry.Pm
        $accessPaths += [PSCustomObject]@{
            Principal=$rbEntry.To; PType="user (direto)"; Level=$riskInfo.Level; Score=$riskInfo.Score
            LevelColor=$riskInfo.Color; LevelIcon=$riskInfo.Icon
            Role="RBAC: $($rbEntry.CR)"; Path="RBAC direto"; Group="-"; Permissions=$permShort
        }
    }
}

$uniquePrincipals = ($accessPaths | Select-Object -Property Principal -Unique).Count
Write-OK "Caminhos: $($accessPaths.Count) para $uniquePrincipals principals"

# Agregar risco por principal (maior score prevalece)
$riskByPrincipal = @{}
foreach ($ap in $accessPaths) {
    if (-not $riskByPrincipal.ContainsKey($ap.Principal)) {
        $riskByPrincipal[$ap.Principal] = @{Score=0;Level="INFO";Color="#8b949e";Icon="&#x26AA;";Paths=0;Roles=@()}
    }
    $riskByPrincipal[$ap.Principal].Paths++
    $riskByPrincipal[$ap.Principal].Roles += $ap.Role
    if ($ap.Score -gt $riskByPrincipal[$ap.Principal].Score) {
        $riskByPrincipal[$ap.Principal].Score = $ap.Score
        $riskByPrincipal[$ap.Principal].Level = $ap.Level
        $riskByPrincipal[$ap.Principal].Color = $ap.LevelColor
        $riskByPrincipal[$ap.Principal].Icon = $ap.LevelIcon
    }
}

$critCount = ($riskByPrincipal.Values | Where-Object { $_.Level -eq "CRITICAL" }).Count
$highCount = ($riskByPrincipal.Values | Where-Object { $_.Level -eq "HIGH" }).Count
$medCount = ($riskByPrincipal.Values | Where-Object { $_.Level -eq "MEDIUM" }).Count
$lowCount = ($riskByPrincipal.Values | Where-Object { $_.Level -eq "LOW" }).Count
Write-OK "Risco: $critCount CRITICAL, $highCount HIGH, $medCount MEDIUM, $lowCount LOW"

# =====================================================================
# 8. EVIDENCIAS DE ALTERACAO RBAC (KQL melhorado)
# =====================================================================
Write-Step "Coletando evidencias de alteracoes RBAC..."
$rbacChanges = @()
try {
    $rbacChanges = Invoke-KQL @'
CloudAppEvents
| where ActionType in ("Add member to role.", "Remove member from role.", "AddRole", "EditRole", "DeleteRole")
| extend RoleName = coalesce(
    tostring(parse_json(tostring(RawEventData.ModifiedProperties[1])).NewValue),
    tostring(parse_json(tostring(RawEventData.ModifiedProperties[0])).NewValue),
    "")
| extend TargetName = coalesce(
    tostring(RawEventData.Target[3].ID),
    tostring(RawEventData.ObjectId),
    "")
| extend TargetType = coalesce(tostring(RawEventData.Target[2].ID), "")
| extend ClientIP = coalesce(IPAddress, "")
| extend Pais = coalesce(CountryCode, "")
| project Timestamp, ActionType, QuemFez=AccountDisplayName, RoleName, TargetName, TargetType, IP=ClientIP, Country=Pais
| sort by Timestamp desc
'@
    Write-OK "Alteracoes de role/RBAC: $($rbacChanges.Count)"
} catch { Write-Warn "Erro ao buscar alteracoes RBAC: $($_.Exception.Message)" }

$rbacGroupChanges = @()
if ($dGrp.Count -gt 0) {
    $grpFilter = ($dGrp | ForEach-Object { "`"$_`"" }) -join ","
    try {
        $rbacGroupChanges = Invoke-KQL "CloudAppEvents | where ActionType in ('Add member to group.','Remove member from group.') | extend GroupName = coalesce(tostring(parse_json(tostring(RawEventData.ModifiedProperties[1])).NewValue),'') | where GroupName has_any ($grpFilter) | extend TargetUPN = coalesce(tostring(RawEventData.ObjectId),'') | extend ClientIP = coalesce(IPAddress,'') | project Timestamp, ActionType, QuemFez=AccountDisplayName, GroupName, TargetUPN, IP=ClientIP | sort by Timestamp desc"
        Write-OK "Alteracoes em grupos RBAC: $($rbacGroupChanges.Count)"
    } catch { Write-Warn "Erro ao buscar alteracoes de grupo RBAC" }
}
$totalRbacChanges = $rbacChanges.Count + $rbacGroupChanges.Count
Write-OK "Total evidencias RBAC: $totalRbacChanges"

# =====================================================================
# 9. KQL QUERIES (melhoradas - extracao de Detalhe e IP)
# =====================================================================
Write-Step "Construindo queries KQL..."
$gf = ""
if ($dGrp.Count -gt 0) {
    $gl = ($dGrp | Select-Object -Unique | ForEach-Object { "`"$_`"" }) -join ", "
    $gf = "| where GroupName has_any ($gl)"
    Write-OK "Filtro de grupos: $gl"
} else {
    $gf = "// Sem grupo especifico do RBAC"
    Write-Warn "Sem grupo RBAC identificado"
}

$kqlFull = @"
CloudAppEvents | where ActionType in ("Add member to role.","Remove member from role.") | extend RoleName = coalesce(tostring(parse_json(tostring(RawEventData.ModifiedProperties[1])).NewValue),"") | where RoleName has_any ("Security Administrator","Security Operator","Security Reader","Global Administrator","Global Reader","Compliance Administrator","Compliance Data Administrator") | project Timestamp, Cenario="1-Role Entra ID", Acao=ActionType, QuemFez=AccountDisplayName, Detalhe=strcat(RoleName," -> ",tostring(RawEventData.ObjectId)), Alvo=coalesce(tostring(RawEventData.ObjectId),""), IP=coalesce(IPAddress,""), Pais=coalesce(CountryCode,"")
| union (CloudAppEvents | where ActionType in ("Add member to group.","Remove member from group.") | extend GroupName = coalesce(tostring(parse_json(tostring(RawEventData.ModifiedProperties[1])).NewValue),"") | project Timestamp, Cenario="2-Grupo Entra ID", Acao=ActionType, QuemFez=AccountDisplayName, Detalhe=GroupName, Alvo=coalesce(tostring(RawEventData.ObjectId),""), IP=coalesce(IPAddress,""), Pais=coalesce(CountryCode,""))
| union (CloudAppEvents | where ActionType in ("AddRole","EditRole","DeleteRole") | project Timestamp, Cenario="3-Custom Role RBAC", Acao=ActionType, QuemFez=AccountDisplayName, Detalhe=coalesce(tostring(parse_json(tostring(RawEventData.ModifiedProperties[0])).NewValue),tostring(RawEventData.ObjectId),""), Alvo="", IP=coalesce(IPAddress,""), Pais=coalesce(CountryCode,""))
| union (IdentityDirectoryEvents | where ActionType == "Group Membership changed" | extend GroupName = tostring(AdditionalFields['TO.GROUP']) | extend RF = tostring(AdditionalFields['FROM.GROUP']) | project Timestamp, Cenario="4-Grupo AD on-prem", Acao=ActionType, QuemFez=AccountDisplayName, Detalhe=coalesce(GroupName,RF,""), Alvo=coalesce(tostring(AdditionalFields['TARGET_OBJECT.USER']),""), IP=coalesce(IPAddress,""), Pais="")
| sort by Timestamp desc
"@

$kqlRule = $kqlFull -replace '2-Grupo Entra ID','2-Grupo RBAC'
if ($dGrp.Count -gt 0) {
    $kqlRule = $kqlRule -replace '\| project Timestamp, Cenario="2-Grupo RBAC"', "$gf`n| project Timestamp, Cenario=`"2-Grupo RBAC`""
}

# =====================================================================
# 10. EXECUTAR ADVANCED HUNTING
# =====================================================================
Write-Step "Executando Advanced Hunting..."
$ev = @()
try { $ev = Invoke-KQL $kqlFull; Write-OK "Eventos: $($ev.Count)" }
catch { Write-Warn "Erro: $($_.Exception.Message)" }
$evS = @{}
foreach ($e in $ev) { $c = $e.Cenario; if (-not $evS.ContainsKey($c)) { $evS[$c] = 0 }; $evS[$c]++ }

$tl = @()
try { $tl = Invoke-KQL "CloudAppEvents|where ActionType in ('Add member to role.','Remove member from role.','Add member to group.','Remove member from group.','AddRole','EditRole','DeleteRole')|summarize Ev=count() by Dia=bin(Timestamp,1d)|sort by Dia asc"; Write-OK "Timeline: $($tl.Count) dias" } catch {}

$ta = @()
try { $ta = Invoke-KQL "CloudAppEvents|where ActionType in ('Add member to role.','Remove member from role.','Add member to group.','Remove member from group.','AddRole','EditRole','DeleteRole')|summarize N=count() by Quem=AccountDisplayName|sort by N desc|take 10" } catch {}

# =====================================================================
# 11. RECOMENDACOES DINAMICAS (baseadas nos achados)
# =====================================================================
Write-Step "Gerando recomendacoes..."
$recommendations = @()

$gaCount = ($rd | Where-Object { $_.Role -eq "Global Administrator" -and $_.Name -ne "(vazio)" }).Count
if ($gaCount -gt 2) {
    $recommendations += @{Sev="CRITICAL";Cat="Least Privilege";Finding="$gaCount Global Administrators ativos";Rec="Reduza para no maximo 2. Use PIM (Privileged Identity Management) para acesso just-in-time.";Ref="CIS Benchmark 1.1 / NIST SP 800-53 AC-6";Link=$portal.PIM}
} elseif ($gaCount -gt 0) {
    $recommendations += @{Sev="INFO";Cat="Least Privilege";Finding="$gaCount Global Administrator(s) - dentro do esperado";Rec="Mantenha monitoramento continuo. Considere PIM para acesso just-in-time.";Ref="CIS Benchmark 1.1";Link=$portal.PIM}
}

$directUserAssignments = ($rd | Where-Object { $_.Typ -eq "user" -and $_.Name -ne "(vazio)" }).Count
if ($directUserAssignments -gt 3) {
    $recommendations += @{Sev="HIGH";Cat="Access Management";Finding="$directUserAssignments atribuicoes diretas de Entra Role a usuarios";Rec="Use grupos de seguranca para gerenciar assignments. Facilita auditoria, revogacao e onboarding/offboarding.";Ref="NIST SP 800-53 AC-2 / Microsoft PAR";Link=$portal.Entra}
}

if ($nS -gt 0) {
    $recommendations += @{Sev="HIGH";Cat="Non-Human Identities";Finding="$nS Service Principal(s) com acesso privilegiado ao XDR";Rec="Revise a necessidade de cada SP. Aplique least privilege, rotacione credenciais e monitore com Workload Identity.";Ref="CIS Benchmark 2.2 / NIST SP 800-53 IA-9";Link=$portal.Entra}
}

$broadRoles = @($rb | Where-Object { $_.Pm -match '\*/manage' -and $_.To -ne "(vazio)" -and $_.To -ne "(indisponivel)" })
if ($broadRoles.Count -gt 0) {
    $recommendations += @{Sev="MEDIUM";Cat="Least Privilege";Finding="$($broadRoles.Count) assignment(s) RBAC com permissoes amplas (*/manage)";Rec="Revise cada role e restrinja as permissoes minimas necessarias por workload.";Ref="NIST SP 800-53 AC-6(1)";Link=$portal.Perms}
}

if ($totalRbacChanges -gt 20) {
    $recommendations += @{Sev="MEDIUM";Cat="Change Management";Finding="$totalRbacChanges alteracoes RBAC nos ultimos $DaysBack dias";Rec="Volume alto de alteracoes. Implemente processo formal de change management e revisao periodica.";Ref="NIST SP 800-53 CM-3";Link=$portal.Audit}
} elseif ($totalRbacChanges -eq 0) {
    $recommendations += @{Sev="INFO";Cat="Monitoring";Finding="Nenhuma alteracao RBAC detectada nos ultimos $DaysBack dias";Rec="Estabilidade confirmada. Mantenha Detection Rule ativa para monitoramento continuo.";Ref="NIST SP 800-53 AU-6";Link=$portal.Hunt}
}

$multiPathPrincipals = ($riskByPrincipal.GetEnumerator() | Where-Object { $_.Value.Paths -gt 2 }).Count
if ($multiPathPrincipals -gt 0) {
    $recommendations += @{Sev="MEDIUM";Cat="Access Hygiene";Finding="$multiPathPrincipals principal(s) com 3+ caminhos de acesso ao XDR";Rec="Principals com multiplos caminhos de acesso dificultam revogacao. Consolide em um unico caminho (grupo RBAC).";Ref="NIST SP 800-53 AC-6(5)";Link=$portal.Perms}
}

# Sempre recomendar access reviews e detection rule
$recommendations += @{Sev="HIGH";Cat="Governance";Finding="Access Reviews periodicas";Rec="Configure Entra ID Access Reviews trimestrais para todas as roles de seguranca. Remova acessos orfaos.";Ref="CIS Benchmark 1.8 / NIST SP 800-53 AC-2(3)";Link=$portal.AccessRev}
$recommendations += @{Sev="HIGH";Cat="Detection";Finding="Detection Rule no Defender XDR";Rec="Crie a Detection Rule (secao 9) para alertar o SOC automaticamente sobre alteracoes RBAC.";Ref="NIST SP 800-53 AU-12 / MITRE T1078";Link=$portal.Hunt}

Write-OK "$($recommendations.Count) recomendacoes geradas"

# =====================================================================
# 12. CONSTRUIR TABELAS HTML
# =====================================================================
Write-Step "Gerando relatorio..."
$tRA = ($rd | Where-Object { $_.Name -ne "(vazio)" }).Count
$tRB = ($rb | Where-Object { $_.To -ne "(vazio)" -and $_.To -ne "(indisponivel)" }).Count
$tEv = $ev.Count

# -- Tabela S1: RBAC Custom Roles (foco principal)
$tblRbac = ""
foreach ($role in $dR.value) {
    $permShort = (($role.rolePermissions | ForEach-Object { $_.allowedResourceActions }) -replace 'microsoft\.xdr/','') -replace '/\*/manage',''
    $assignments = $dA.value | Where-Object { $_.roleDefinitionId -eq $role.id }
    if ($assignments.Count -eq 0) {
        $tblRbac += "<tr><td style='color:#3fb950;font-weight:600'><a href='$($portal.Perms)' target='_blank' style='color:#3fb950;text-decoration:none'>$($role.displayName)</a></td><td class='sm'>$permShort</td><td colspan='3' style='color:#6e7681'>(sem assignment)</td></tr>`n"
    } else {
        foreach ($a in $assignments) {
            foreach ($principalId in $a.principalIds) {
                $obj3 = Get-MgDirectoryObject -DirectoryObjectId $principalId -ErrorAction SilentlyContinue
                $ot3 = $obj3.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''
                $on3 = $obj3.AdditionalProperties.displayName
                $scope3 = if ($a.appScopeIds -contains "/") { "Global (todos workloads)" } else { $a.appScopeIds -join "," }
                $memberList3 = "-"
                if ($ot3 -eq 'group') {
                    $ms3 = Get-MgGroupMember -GroupId $principalId -ErrorAction SilentlyContinue
                    $memberList3 = ($ms3 | ForEach-Object { "$($_.AdditionalProperties.displayName)" }) -join ", "
                    if (-not $memberList3) { $memberList3 = "(vazio)" }
                }
                $typeBC3 = if ($ot3 -eq 'group') { "#3fb95033;color:#3fb950" } else { "#1f6feb33;color:#58a6ff" }
                $tblRbac += "<tr><td style='color:#3fb950;font-weight:600'><a href='$($portal.Perms)' target='_blank' style='color:#3fb950;text-decoration:none'>$($role.displayName)</a></td><td class='sm'>$permShort</td><td><span class='badge' style='background:$typeBC3'>$ot3</span> <b>$on3</b></td><td>$scope3</td><td>$memberList3</td></tr>`n"
            }
        }
    }
}

# -- Tabela S2: Matriz de Permissoes (visual rica)
$tblPermMatrix = ""
foreach ($pm in $permMatrix) {
    $tblPermMatrix += "<tr><td style='color:#3fb950;font-weight:600'>$($pm.RoleName)</td>"
    foreach ($cat in $permCatDefs) {
        $lvl = $pm.Cats[$cat.Key]
        $cellStyle = if ($lvl -eq "manage") { "background:linear-gradient(135deg,#f8514930,#f8514910);color:#f85149;font-weight:700;border:1px solid #f8514940" } elseif ($lvl -eq "read") { "background:linear-gradient(135deg,#3fb95030,#3fb95010);color:#3fb950;font-weight:600;border:1px solid #3fb95040" } else { "color:#30363d" }
        $cellIcon = if ($lvl -eq "manage") { "<div style='font-size:14px'>&#x1F534;</div><div style='font-size:9px;margin-top:2px'>MANAGE</div>" } elseif ($lvl -eq "read") { "<div style='font-size:14px'>&#x1F7E2;</div><div style='font-size:9px;margin-top:2px'>READ</div>" } else { "<div style='color:#30363d'>---</div>" }
        $tblPermMatrix += "<td style='$cellStyle;text-align:center;padding:10px 8px;border-radius:6px'>$cellIcon</td>"
    }
    $tblPermMatrix += "</tr>`n"
}

# -- Tabela S3: Risk Analysis (com barras visuais)
$tblRisk = ""
foreach ($entry in ($riskByPrincipal.GetEnumerator() | Sort-Object { $_.Value.Score } -Descending)) {
    $r = $entry.Value
    $rolesUnique = ($r.Roles | Select-Object -Unique) -join ", "
    $riskBadge = "<span class='badge' style='background:$($r.Color)22;color:$($r.Color)'>$($r.Icon) $($r.Level)</span>"
    $pathsBadge = if ($r.Paths -gt 2) { "<span class='badge' style='background:#d2992233;color:#d29922'>$($r.Paths) caminhos</span>" } else { "$($r.Paths)" }
    $scoreBar = "<div style='display:flex;align-items:center;gap:6px'><div style='width:$($r.Score)px;height:8px;background:$($r.Color);border-radius:4px;opacity:.7'></div><span style='color:$($r.Color);font-weight:700;font-size:12px'>$($r.Score)</span></div>"
    $tblRisk += "<tr style='border-left:3px solid $($r.Color)'><td><b>$($entry.Key)</b></td><td>$riskBadge</td><td>$scoreBar</td><td style='text-align:center'>$pathsBadge</td><td class='sm'>$rolesUnique</td></tr>`n"
}

# -- SVG: Risk Gauge (distribuicao visual)
$riskTotal = [Math]::Max($riskByPrincipal.Count, 1)
$critPct = [Math]::Round(($critCount / $riskTotal) * 300)
$highPct = [Math]::Round(($highCount / $riskTotal) * 300)
$medPct = [Math]::Round(($medCount / $riskTotal) * 300)
$lowPct = [Math]::Round(($lowCount / $riskTotal) * 300)
$svgRisk = "<rect x='0' y='0' width='300' height='24' rx='12' fill='#161b22' stroke='#30363d' stroke-width='1'/>"
$rx = 0
if ($critPct -gt 0) { $svgRisk += "<rect x='$rx' y='0' width='$critPct' height='24' rx='$(if($rx -eq 0){12}else{0})' fill='#f85149' opacity='.85'><title>CRITICAL: $critCount</title></rect>"; $rx += $critPct }
if ($highPct -gt 0) { $svgRisk += "<rect x='$rx' y='0' width='$highPct' height='24' fill='#ff7b72' opacity='.85'><title>HIGH: $highCount</title></rect>"; $rx += $highPct }
if ($medPct -gt 0) { $svgRisk += "<rect x='$rx' y='0' width='$medPct' height='24' fill='#d29922' opacity='.85'><title>MEDIUM: $medCount</title></rect>"; $rx += $medPct }
if ($lowPct -gt 0) { $svgRisk += "<rect x='$rx' y='0' width='$lowPct' height='24' fill='#3fb950' opacity='.85'><title>LOW: $lowCount</title></rect>" }
$svgRisk += "<text x='150' y='16' fill='white' font-family='Segoe UI' font-size='10' text-anchor='middle' font-weight='700' style='text-shadow:0 1px 2px rgba(0,0,0,.5)'>$critCount CRITICAL / $highCount HIGH / $medCount MED / $lowCount LOW</text>"

# -- Tabela S4: Evidencias RBAC
$tblEvidence = ""
foreach ($rc in $rbacChanges) {
    $actionColor = if ($rc.ActionType -match "Add") { "#3fb950" } elseif ($rc.ActionType -match "Remove") { "#f85149" } else { "#d29922" }
    $actionIcon = if ($rc.ActionType -match "Add") { "&#x2795;" } elseif ($rc.ActionType -match "Remove") { "&#x274C;" } else { "&#x270F;&#xFE0F;" }
    $ts2 = ([datetime]$rc.Timestamp).ToString("yyyy-MM-dd HH:mm")
    $ipDisplay = if ($rc.IP) { $rc.IP } else { "-" }
    $countryDisplay = if ($rc.Country) { " ($($rc.Country))" } else { "" }
    $tblEvidence += "<tr style='border-left:3px solid $actionColor'><td class='mono'>$ts2</td><td style='color:$actionColor;font-weight:600'>$actionIcon $($rc.ActionType)</td><td><b>$($rc.QuemFez)</b></td><td>$(HtmlEncode $rc.RoleName)</td><td>$(HtmlEncode $rc.TargetName) <span style='color:#6e7681;font-size:9px'>$(HtmlEncode $rc.TargetType)</span></td><td class='mono'>$ipDisplay$countryDisplay</td></tr>`n"
}
foreach ($gc in $rbacGroupChanges) {
    $actionColor = if ($gc.ActionType -match "Add") { "#3fb950" } else { "#f85149" }
    $actionIcon = if ($gc.ActionType -match "Add") { "&#x2795;" } else { "&#x274C;" }
    $ts2 = ([datetime]$gc.Timestamp).ToString("yyyy-MM-dd HH:mm")
    $ipDisplay = if ($gc.IP) { $gc.IP } else { "-" }
    $tblEvidence += "<tr style='border-left:3px solid $actionColor'><td class='mono'>$ts2</td><td style='color:$actionColor;font-weight:600'>$actionIcon Grupo RBAC</td><td><b>$($gc.QuemFez)</b></td><td>$(HtmlEncode $gc.GroupName)</td><td>$(HtmlEncode $gc.TargetUPN)</td><td class='mono'>$ipDisplay</td></tr>`n"
}

# -- Tabela S5: Entra ID Roles / Caminhos de Acesso (com links clicaveis)
$tblAccess = ""
foreach ($ap in ($accessPaths | Sort-Object Score -Descending)) {
    $typeBC = switch -Wildcard ($ap.PType) {
        "user*" { "#1f6feb33;color:#58a6ff" }
        "group" { "#3fb95033;color:#3fb950" }
        "servicePrincipal" { "#d2992233;color:#d29922" }
        default { "#30363d;color:#8b949e" }
    }
    $pathLink = if ($ap.Path -match "Entra") { "<a href='$($portal.Entra)' target='_blank' style='color:#58a6ff;text-decoration:none'>$($ap.Path)</a>" } else { "<a href='$($portal.Perms)' target='_blank' style='color:#3fb950;text-decoration:none'>$($ap.Path)</a>" }
    $groupInfo = if ($ap.Group -ne "-") { "<br><span style='color:#3fb950;font-size:9px'>via $($ap.Group)</span>" } else { "" }
    $riskBadge = "<span class='badge' style='background:$($ap.LevelColor)22;color:$($ap.LevelColor)'>$($ap.LevelIcon) $($ap.Level)</span>"
    $tblAccess += "<tr><td><b>$($ap.Principal)</b>$groupInfo</td><td><span class='badge' style='background:$typeBC'>$($ap.PType)</span></td><td>$riskBadge</td><td>$($ap.Role)</td><td>$pathLink</td></tr>`n"
}

# -- SVG: Mapa de Arquitetura RBAC
$svgNodes = ""
$svgLines = ""
$sy = 55
$wlPositions = @()

foreach ($w in $wl) {
    $op = if ($w.A) { "1" } else { ".3" }
    $sc = if ($w.A) { $w.C } else { "#484f58" }
    $stTxt = if ($w.A) { "Ativo - dados no Advanced Hunting" } else { "Sem dados - verificar conector" }
    $svgNodes += "<g transform='translate(10,$sy)' opacity='$op' style='cursor:pointer'><title>$($w.F)`n$stTxt</title><rect width='125' height='30' rx='6' fill='#161b22' stroke='$sc' stroke-width='1.3'/><text x='8' y='13' fill='$sc' font-family='Segoe UI' font-size='7.5' font-weight='700'>$($w.N)</text><text x='8' y='24' fill='#6e7681' font-family='Segoe UI' font-size='5.5'>$($w.F)</text>"
    $statusDot = if ($w.A) { "#3fb950" } else { "#f85149" }
    $svgNodes += "<circle cx='116' cy='8' r='3.5' fill='$statusDot'/></g>`n"
    $wlPositions += @{Y=$sy;C=$sc;Op=$op}
    $sy += 38
}

# Roles/Grupos a direita com cores de risco
$ry = 55
$rightNodes = @()
$rC = @{"Global Administrator"="#f85149";"Security Administrator"="#ff7b72";"Security Operator"="#ffa657";"Security Reader"="#d29922";"Global Reader"="#79c0ff";"Compliance Administrator"="#a5d6ff";"Compliance Data Administrator"="#7ee787"}

foreach ($rn in ($rd | Where-Object { $_.Name -ne "(vazio)" } | Select-Object -Property Role -Unique).Role) {
    $mc = ($rd | Where-Object { $_.Role -eq $rn -and $_.Name -ne "(vazio)" }).Count
    $co = if ($rC.ContainsKey($rn)) { $rC[$rn] } else { "#8b949e" }
    $memberNames = ($rd | Where-Object { $_.Role -eq $rn -and $_.Name -ne "(vazio)" } | ForEach-Object { "  $($_.Name) ($($_.Typ))" }) -join "`n"
    $riskLvl = (Get-RiskInfo -Role $rn -Permissions "").Level
    $rightNodes += @{Y=$ry;N=$rn;C=$co;Cnt=$mc;Type="role";Risk=$riskLvl;Tip="$rn (Entra ID Role)`nRisco: $riskLvl`nEscopo: TODOS os workloads`n$mc membro(s):`n$memberNames"}
    $ry += 30
}
foreach ($g in $dGrp) {
    $rbM = $rb | Where-Object { $_.To -eq $g } | Select-Object -First 1
    $gMemberCount = if ($rbM.Mb -and $rbM.Mb -ne "(vazio)" -and $rbM.Mb -ne "-") { ($rbM.Mb -split ",").Count } else { 0 }
    $permShort = ($rbM.Pm -replace 'microsoft\.xdr/','') -replace '/\*/manage',''
    $scopeTxt = if ($rbM.Scope -match "Global") { "Global (todos workloads)" } else { $rbM.Scope }
    $gTip = "Grupo RBAC: $g`nCustom Role: $($rbM.CR)`nEscopo: $scopeTxt`nPermissoes: $permShort`nMembros ($gMemberCount): $($rbM.Mb)"
    $rightNodes += @{Y=$ry;N=$g;C="#3fb950";Cnt=$gMemberCount;Type="group";Risk="RBAC";Tip=$gTip;Perms=$permShort}
    $ry += 30
}

# Centro: XDR Portal
$centerY = [Math]::Max(65, [Math]::Floor(([Math]::Max($sy, $ry) / 2) - 25))
$svgNodes += "<g style='cursor:pointer'><title>Microsoft Defender XDR`nPortal: security.microsoft.com`nModelo: Unified RBAC</title>"
$svgNodes += "<rect x='195' y='$centerY' width='95' height='44' rx='8' fill='#21262d' stroke='#58a6ff' stroke-width='1.5'/>"
$svgNodes += "<text x='242' y='$($centerY+19)' fill='#58a6ff' font-family='Segoe UI' font-size='7.5' text-anchor='middle' font-weight='700'>DEFENDER XDR</text>"
$svgNodes += "<text x='242' y='$($centerY+32)' fill='#6e7681' font-family='Segoe UI' font-size='5.5' text-anchor='middle'>Unified RBAC</text></g>`n"

# Linhas workloads -> centro
foreach ($wp in $wlPositions) {
    $svgLines += "<line x1='135' y1='$($wp.Y+15)' x2='195' y2='$($centerY+22)' stroke='$($wp.C)' stroke-width='.7' stroke-dasharray='3' opacity='$($wp.Op)'/>`n"
}

# Nos direita + linhas centro -> roles/grupos
foreach ($rn in $rightNodes) {
    $typeIcon = if ($rn.Type -eq "role") { "&#x1F511;" } else { "&#x1F465;" }
    $cntBadge = ""
    if ($rn.Cnt -gt 0) {
        $badgeFill = if ($rn.Type -eq "group") { "#3fb950" } else { $rn.C }
        $cntBadge = "<rect x='138' y='3' width='18' height='14' rx='7' fill='${badgeFill}20' stroke='$badgeFill' stroke-width='.5'/><text x='147' y='13' fill='$badgeFill' font-family='Segoe UI' font-size='6.5' text-anchor='middle' font-weight='700'>$($rn.Cnt)</text>"
    }
    $tipEscaped = $rn.Tip -replace "'","&#39;"
    $svgNodes += "<g transform='translate(330,$($rn.Y))' style='cursor:pointer'><title>$tipEscaped</title>"
    $svgNodes += "<rect width='160' height='22' rx='5' fill='$($rn.C)08' stroke='$($rn.C)' stroke-width='.8'/>"
    $svgNodes += "<text x='5' y='14' fill='$($rn.C)' font-family='Segoe UI' font-size='6.5' font-weight='600'>$typeIcon $($rn.N)</text>"
    $svgNodes += "$cntBadge</g>`n"
    if ($rn.Type -eq 'group' -and $rn.Perms) {
        $svgNodes += "<text x='335' y='$($rn.Y+30)' fill='#3fb95080' font-family='Segoe UI' font-size='4.5' font-style='italic'>$($rn.Perms)</text>`n"
    }
    $svgLines += "<line x1='290' y1='$($centerY+22)' x2='330' y2='$($rn.Y+11)' stroke='$($rn.C)' stroke-width='.6' stroke-dasharray='3' opacity='.35'/>`n"
}

$svg1 = $svgLines + $svgNodes
# Legenda SVG
$legendY = [Math]::Max($sy, $ry) + 28
$svg1 += "<line x1='10' y1='$($legendY-10)' x2='510' y2='$($legendY-10)' stroke='#21262d' stroke-width='.5'/>`n"
$svg1 += "<g transform='translate(10,$legendY)' font-family='Segoe UI'>`n"
$svg1 += "<text x='0' y='10' fill='#484f58' font-size='7' font-weight='700'>STATUS:</text>"
$svg1 += "<circle cx='50' cy='7' r='3' fill='#3fb950'/><text x='57' y='10' fill='#6e7681' font-size='7'>Ativo</text>"
$svg1 += "<circle cx='88' cy='7' r='3' fill='#f85149'/><text x='95' y='10' fill='#6e7681' font-size='7'>Inativo</text>`n"
$svg1 += "<text x='140' y='10' fill='#484f58' font-size='7' font-weight='700'>TIPO:</text>"
$svg1 += "<rect x='170' y='1' width='8' height='8' rx='2' fill='#f8514920' stroke='#f85149' stroke-width='.5'/><text x='182' y='10' fill='#6e7681' font-size='7'>Entra ID Role</text>"
$svg1 += "<rect x='245' y='1' width='8' height='8' rx='2' fill='#3fb95020' stroke='#3fb950' stroke-width='.5'/><text x='257' y='10' fill='#6e7681' font-size='7'>Grupo RBAC</text>`n"
$svg1 += "<text x='0' y='24' fill='#484f58' font-size='6' font-style='italic'>Passe o mouse sobre qualquer elemento para ver detalhes (membros, permissoes, risco)</text></g>`n"
$svgH1 = $legendY + 42

# -- SVG: Donut
$svgD = ""
$dC = @{"1-Role Entra ID"="#f85149";"2-Grupo Entra ID"="#58a6ff";"3-Custom Role RBAC"="#3fb950";"4-Grupo AD on-prem"="#d29922"}
$dLabels = @{"1-Role Entra ID"="Atribuicao/remocao de Entra ID Role";"2-Grupo Entra ID"="Alteracao de membership em grupo";"3-Custom Role RBAC"="Criacao/edicao de role RBAC";"4-Grupo AD on-prem"="Alteracao de grupo AD on-prem"}
if ($evS.Count -gt 0 -and $tEv -gt 0) {
    $sa = 0
    foreach ($en in $evS.GetEnumerator()) {
        $pc = $en.Value / $tEv
        $ea = $sa + ($pc * 360)
        $sr = $sa * [Math]::PI / 180; $er = $ea * [Math]::PI / 180
        $cx = 90; $cy = 90; $rad = 70
        $x1 = $cx + $rad * [Math]::Cos($sr); $y1 = $cy + $rad * [Math]::Sin($sr)
        $x2 = $cx + $rad * [Math]::Cos($er); $y2 = $cy + $rad * [Math]::Sin($er)
        $la = if ($pc -gt .5) { 1 } else { 0 }
        $cl = if ($dC.ContainsKey($en.Key)) { $dC[$en.Key] } else { "#8b949e" }
        if ($pc -lt 1) {
            $svgD += "<path d='M $cx $cy L $([Math]::Round($x1,2)) $([Math]::Round($y1,2)) A $rad $rad 0 $la 1 $([Math]::Round($x2,2)) $([Math]::Round($y2,2)) Z' fill='$cl' opacity='.85'><title>$($en.Key): $($en.Value) ($([Math]::Round($pc*100))%)</title></path>`n"
        } else {
            $svgD += "<circle cx='$cx' cy='$cy' r='$rad' fill='$cl' opacity='.85'/>`n"
        }
        $sa = $ea
    }
    $svgD += "<circle cx='90' cy='90' r='38' fill='#0d1117'/><text x='90' y='86' fill='#c9d1d9' font-size='18' text-anchor='middle' font-weight='700' font-family='Segoe UI'>$tEv</text><text x='90' y='102' fill='#8b949e' font-size='9' text-anchor='middle' font-family='Segoe UI'>eventos</text>`n"
    $ly = 20
    foreach ($en in $evS.GetEnumerator()) {
        $cl = if ($dC.ContainsKey($en.Key)) { $dC[$en.Key] } else { "#8b949e" }
        $pp = [Math]::Round(($en.Value / [Math]::Max($tEv,1)) * 100)
        $desc = if ($dLabels.ContainsKey($en.Key)) { $dLabels[$en.Key] } else { $en.Key }
        $svgD += "<rect x='195' y='$ly' width='10' height='10' rx='2' fill='$cl'/><text x='210' y='$($ly+9)' fill='#c9d1d9' font-size='10' font-weight='600' font-family='Segoe UI'>$($en.Key)</text><text x='210' y='$($ly+22)' fill='#6e7681' font-size='8' font-family='Segoe UI'>$desc - $($en.Value) ($($pp)%)</text>`n"
        $ly += 36
    }
}

# -- SVG: Top Atores
$svgA = ""
if ($ta.Count -gt 0) {
    $ma = ($ta | ForEach-Object { [int]$_.N } | Measure-Object -Maximum).Maximum
    if ($ma -eq 0) { $ma = 1 }
    $ay = 10
    foreach ($ac in $ta) {
        $bw = [Math]::Max(5, [Math]::Floor(([int]$ac.N / $ma) * 280))
        $pct = [Math]::Round(([int]$ac.N / $tEv) * 100)
        $barCol = if ($pct -gt 40) { "#f85149" } elseif ($pct -gt 20) { "#d29922" } else { "#58a6ff" }
        $svgA += "<rect x='150' y='$ay' width='$bw' height='18' rx='3' fill='$barCol' opacity='.6'/><text x='145' y='$($ay+13)' fill='#c9d1d9' font-size='9' text-anchor='end' font-family='Segoe UI'>$($ac.Quem)</text><text x='$($bw+158)' y='$($ay+13)' fill='$barCol' font-size='9' font-weight='600' font-family='Segoe UI'>$($ac.N) ($($pct)%)</text>`n"
        $ay += 26
    }
}
$aH = [Math]::Max(60, ($ta.Count * 26) + 15)

# -- SVG: Timeline
$svgT = ""
if ($tl.Count -gt 0) {
    $mx = ($tl | ForEach-Object { [int]$_.Ev } | Measure-Object -Maximum).Maximum
    if ($mx -eq 0) { $mx = 1 }
    $bw = [Math]::Floor(650 / [Math]::Max($tl.Count,1))
    $bx = 80
    $svgT += "<text x='10' y='20' fill='#484f58' font-size='8' font-family='Segoe UI'>$mx</text><line x1='80' y1='18' x2='750' y2='18' stroke='#21262d' stroke-width='.5'/>`n"
    $svgT += "<text x='10' y='100' fill='#484f58' font-size='8' font-family='Segoe UI'>$([Math]::Floor($mx/2))</text><line x1='80' y1='98' x2='750' y2='98' stroke='#21262d' stroke-width='.5'/>`n"
    $svgT += "<line x1='80' y1='180' x2='750' y2='180' stroke='#30363d' stroke-width='1'/><line x1='80' y1='18' x2='80' y2='180' stroke='#30363d' stroke-width='1'/>`n"
    $svgT += "<text x='10' y='183' fill='#484f58' font-size='8' font-family='Segoe UI'>0</text>`n"
    foreach ($td in $tl) {
        $bh = [Math]::Max(3, [Math]::Floor(([int]$td.Ev / $mx) * 160))
        $by = 180 - $bh
        $dl = ([datetime]$td.Dia).ToString("MM/dd")
        $barC = if ([int]$td.Ev -gt ($mx * 0.7)) { "#f85149" } elseif ([int]$td.Ev -gt ($mx * 0.3)) { "#d29922" } else { "#58a6ff" }
        $svgT += "<rect x='$bx' y='$by' width='$([Math]::Max($bw-4,6))' height='$bh' rx='3' fill='$barC' opacity='.7'><title>$dl : $($td.Ev) eventos</title></rect>`n"
        $svgT += "<text x='$($bx+($bw/2)-4)' y='$($by-3)' fill='$barC' font-size='8' font-weight='600' font-family='Segoe UI'>$($td.Ev)</text>`n"
        $svgT += "<text x='$($bx+($bw/2)-6)' y='196' fill='#484f58' font-size='7' font-family='Segoe UI' transform='rotate(-45 $($bx+($bw/2)-6) 196)'>$dl</text>`n"
        $bx += $bw
    }
}

# -- Tabela S7: Eventos
$tblEv = ($ev | Select-Object -First 50 | ForEach-Object {
    $sv = if ($_.Cenario -match "1-Role|3-Custom") { "border-left:3px solid #f85149" } else { "border-left:3px solid #d29922" }
    $ipCell = if ($_.IP) { $_.IP } else { "-" }
    $paisCell = if ($_.Pais) { " ($($_.Pais))" } else { "" }
    $detailCell = if ($_.Detalhe) { HtmlEncode $_.Detalhe } else { "-" }
    "<tr style='$sv'><td class='mono'>$(([datetime]$_.Timestamp).ToString('yyyy-MM-dd HH:mm'))</td><td>$($_.Cenario)</td><td>$($_.Acao)</td><td>$($_.QuemFez)</td><td class='sm'>$detailCell</td><td>$(HtmlEncode $_.Alvo)</td><td class='mono'>$ipCell$paisCell</td></tr>"
}) -join "`n"

# -- Tabela S10: Recomendacoes
$tblRecs = ""
foreach ($rec in ($recommendations | Sort-Object { switch ($_.Sev) { "CRITICAL" {0} "HIGH" {1} "MEDIUM" {2} "LOW" {3} "INFO" {4} default {5} } })) {
    $sevColor = switch ($rec.Sev) { "CRITICAL" {"#f85149"} "HIGH" {"#ff7b72"} "MEDIUM" {"#d29922"} "LOW" {"#3fb950"} "INFO" {"#8b949e"} default {"#8b949e"} }
    $sevBg = switch ($rec.Sev) { "CRITICAL" {"#f8514920"} "HIGH" {"#ff7b7220"} "MEDIUM" {"#d2992220"} "LOW" {"#3fb95020"} "INFO" {"#8b949e20"} default {"#8b949e20"} }
    $linkHtml = if ($rec.Link) { "<br><a href='$($rec.Link)' target='_blank' style='color:#58a6ff;font-size:9px'>Abrir no Portal &#x2192;</a>" } else { "" }
    $tblRecs += "<tr style='border-left:3px solid $sevColor'><td><span class='badge' style='background:$sevBg;color:$sevColor'>$($rec.Sev)</span></td><td style='color:#8b949e'>$($rec.Cat)</td><td><b>$($rec.Finding)</b></td><td>$($rec.Rec)$linkHtml</td><td class='sm'>$($rec.Ref)</td></tr>`n"
}

# Escape KQL para HTML
$kH = $kqlFull -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
$kR = $kqlRule -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
$tmask = Mask $ctx.TenantId

# =====================================================================
# 13. HTML REPORT
# =====================================================================
$htmlContent = @"
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Defender XDR RBAC Audit v2.0</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6;font-size:13px}
.c{max-width:1440px;margin:0 auto;padding:20px}
.hd{background:linear-gradient(135deg,#1a1f35 0%,#0a2647 50%,#0d1117 100%);border:1px solid #30363d;border-radius:12px;padding:30px;margin-bottom:20px;position:relative;overflow:hidden}
.hd::before{content:'';position:absolute;top:-50%;right:-10%;width:300px;height:300px;background:radial-gradient(circle,#58a6ff08,transparent);pointer-events:none}
.hd h1{color:#58a6ff;font-size:24px;font-weight:700;letter-spacing:-.3px}.hd p{color:#8b949e;font-size:12px;margin-top:4px}
.hd .mt{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap;font-size:11px}
.hd .mt span,.hd .mt a{background:#21262d;padding:4px 12px;border-radius:6px;border:1px solid #30363d;color:#8b949e;text-decoration:none;transition:all .2s}
.hd .mt a:hover{color:#58a6ff;border-color:#58a6ff;background:#161b22}
.cds{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px}
.cd{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;text-align:center;transition:all .2s;position:relative;overflow:hidden}
.cd::before{content:'';position:absolute;top:0;left:0;width:4px;height:100%;border-radius:10px 0 0 10px}
.cd:hover{transform:translateY(-3px);box-shadow:0 4px 12px rgba(0,0,0,.3)}
.cd .n{font-size:32px;font-weight:800}.cd .l{color:#8b949e;font-size:10px;margin-top:3px;line-height:1.4}
.cd.c1 .n{color:#58a6ff}.cd.c1::before{background:#58a6ff}
.cd.c2 .n{color:#3fb950}.cd.c2::before{background:#3fb950}
.cd.c3 .n{color:#d29922}.cd.c3::before{background:#d29922}
.cd.c4 .n{color:#f85149}.cd.c4::before{background:#f85149}
.cd.c5 .n{color:#ce93d8}.cd.c5::before{background:#ce93d8}
.cd.c6 .n{color:#ff7b72}.cd.c6::before{background:#ff7b72}
.sc{background:#161b22;border:1px solid #30363d;border-radius:10px;margin-bottom:20px;overflow:hidden}
.st{background:#21262d;padding:12px 18px;font-size:14px;font-weight:600;color:#58a6ff;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;align-items:center}
.st a{font-size:10px;color:#6e7681;text-decoration:none;background:#161b22;padding:3px 10px;border-radius:5px;border:1px solid #30363d;transition:all .2s}
.st a:hover{color:#58a6ff;border-color:#58a6ff}
.sb{padding:18px;overflow-x:auto}
.rt{background:#0d1117;border-left:3px solid #1f6feb44;border-radius:0 8px 8px 0;padding:14px 16px;margin-bottom:16px;color:#8b949e;font-size:11px;line-height:1.8}
.rt b{color:#c9d1d9}.rt a{color:#58a6ff;text-decoration:none}.rt a:hover{text-decoration:underline}
.rt code{background:#21262d;padding:1px 5px;border-radius:4px;font-size:10px;font-family:'Cascadia Code',Consolas,monospace}
table{width:100%;border-collapse:collapse;font-size:11px;font-family:'Segoe UI',sans-serif}
th{background:#21262d;color:#58a6ff;padding:8px 10px;text-align:left;border-bottom:2px solid #30363d;position:sticky;top:0;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.3px}
td{padding:7px 10px;border-bottom:1px solid #1c2128}
tr:hover{background:#1c2128}
.mono{font-family:'Cascadia Code',Consolas,monospace;font-size:10px;color:#6e7681}
.sm{font-size:10px;color:#6e7681;max-width:320px;word-wrap:break-word}
.badge{padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600;display:inline-block}
.kql{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:14px;font-family:'Cascadia Code',Consolas,monospace;font-size:10px;white-space:pre-wrap;color:#c9d1d9;max-height:320px;overflow-y:auto;line-height:1.7}
.cp{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:5px 12px;cursor:pointer;font-size:10px;float:right;font-family:'Segoe UI',sans-serif;transition:all .2s}
.cp:hover{background:#30363d;color:#58a6ff;border-color:#58a6ff}
.ins{background:#0d1117;border-left:3px solid #1f6feb;border-radius:0 8px 8px 0;padding:12px 16px;margin:14px 0;font-size:11px}
.ins h3{color:#58a6ff;font-size:12px;margin-bottom:6px;font-weight:600}
.ins ol{padding-left:18px}.ins code{background:#21262d;padding:1px 5px;border-radius:4px;font-size:10px;font-family:'Cascadia Code',Consolas,monospace}
.gr{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:900px){.gr{grid-template-columns:1fr}}
.ft{text-align:center;padding:24px;margin-top:20px;border-top:1px solid #21262d}
.ft .brand{color:#58a6ff;font-size:14px;font-weight:700;margin-bottom:4px}
.ft .brand a{color:#58a6ff;text-decoration:none}
.ft .sub{color:#484f58;font-size:10px;line-height:1.6}
</style></head><body><div class="c">

<!-- HEADER -->
<div class="hd">
<h1>&#x1F6E1;&#xFE0F; Defender XDR - RBAC Audit Report v2.0</h1>
<p>Auditoria estado-da-arte de permissoes, custom roles, categorias, risco e eventos do Unified RBAC</p>
<div class="mt">
<span>&#x1F4C5; $ts</span><span>&#x1F464; $($ctx.Account)</span><span>&#x1F3E2; $tmask</span><span>&#x1F4CA; $DaysBack dias</span><span>&#x1F4BB; v$scriptVersion</span>
<a href="$($portal.Perms)" target="_blank">&#x1F512; Permissions</a>
<a href="$($portal.Hunt)" target="_blank">&#x1F50E; Advanced Hunting</a>
<a href="$($portal.Audit)" target="_blank">&#x1F4DD; Audit Log</a>
<a href="$($portal.Entra)" target="_blank">&#x1F511; Entra Roles</a>
<a href="$($portal.SecScore)" target="_blank">&#x1F3AF; Secure Score</a>
<a href="$($portal.Incidents)" target="_blank">&#x1F6A8; Incidents</a>
</div></div>

<!-- KPI CARDS -->
<div class="cds">
<div class="cd c2"><div class="n">$($dR.value.Count)</div><div class="l">Custom Roles<br>Unified RBAC</div></div>
<div class="cd c4"><div class="n">$critCount</div><div class="l">Principals<br>Risco CRITICAL</div></div>
<div class="cd c1"><div class="n">$tRA</div><div class="l">Entra ID Roles<br>Ativas</div></div>
<div class="cd c3"><div class="n">$totalRbacChanges</div><div class="l">Alteracoes RBAC<br>($DaysBack dias)</div></div>
<div class="cd c5"><div class="n">$aWL<span style='font-size:14px;color:#6e7681'>/4</span></div><div class="l">Workloads<br>Ativos</div></div>
<div class="cd c6"><div class="n">$($recommendations.Count)</div><div class="l">Recomendacoes<br>CIS/NIST</div></div>
</div>

<!-- S1: RBAC CUSTOM ROLES -->
<div class="sc"><div class="st" style="background:#1a2e1a">&#x1F512; 1. RBAC do Defender XDR -- Custom Roles e Assignments<a href="$($portal.Perms)" target="_blank">Permissions &#x2192;</a></div><div class="sb">
<div class="rt" style="border-left-color:#3fb950;padding:8px 14px"><b>$($dR.value.Count)</b> custom role(s), <b>$($dGrp.Count)</b> grupo(s), <b>$tRB</b> assignment(s). Roles atribuidas a grupos Entra ID -- membros herdam permissoes. &#x1F517; <a href="$($portal.Perms)" target="_blank">Portal</a> | <a href="https://learn.microsoft.com/defender-xdr/custom-permissions-details" target="_blank">Docs</a></div>
<div style="overflow-x:auto"><table style="min-width:950px"><thead><tr><th style="min-width:140px">Custom Role</th><th style="min-width:220px">Permissoes</th><th style="min-width:200px">Atribuida a</th><th style="min-width:150px">Escopo</th><th style="min-width:220px">Membros (acesso efetivo)</th></tr></thead><tbody>
$tblRbac
</tbody></table></div></div></div>

<!-- S2: PERMISSION CATEGORIES MATRIX -->
<div class="sc"><div class="st">&#x1F4CB; 2. Matriz de Permissoes por Categoria RBAC<a href="https://learn.microsoft.com/defender-xdr/custom-permissions-details" target="_blank">Docs &#x2192;</a></div><div class="sb">
<div class="rt" style="padding:8px 14px"><span style="color:#f85149">&#x1F534; MANAGE</span> = leitura + escrita + acoes | <span style="color:#3fb950">&#x1F7E2; READ</span> = somente leitura. 4 categorias: SecOps, Posture, Auth/Settings, DataOps.</div>
<div style="overflow-x:auto"><table style="min-width:700px"><thead><tr><th style="min-width:160px">Custom Role</th><th style="min-width:120px;text-align:center">&#x1F6E1;&#xFE0F; Security Ops</th><th style="min-width:120px;text-align:center">&#x1F4CA; Sec. Posture</th><th style="min-width:120px;text-align:center">&#x2699;&#xFE0F; Auth/Settings</th><th style="min-width:120px;text-align:center">&#x1F4BE; Data Ops</th></tr></thead><tbody>
$tblPermMatrix
</tbody></table></div></div></div>

<!-- S3: RISK ANALYSIS -->
<div class="sc"><div class="st">&#x26A0;&#xFE0F; 3. Analise de Risco por Principal</div><div class="sb">
<svg viewBox="0 0 300 24" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:800px;height:28px;margin-bottom:12px">$svgRisk</svg>
<div class="rt" style="padding:8px 14px">Score por <b>maior privilegio</b>. <span style="color:#f85149">&#x1F534; CRITICAL</span> Global/Sec Admin | <span style="color:#ff7b72">&#x1F7E0; HIGH</span> Operator/SecOps manage | <span style="color:#d29922">&#x1F7E1; MEDIUM</span> Posture/Config | <span style="color:#3fb950">&#x1F7E2; LOW</span> Read-only</div>
<div style="overflow-x:auto"><table style="min-width:750px"><thead><tr><th style="min-width:180px">Principal</th><th style="min-width:120px">Nivel de Risco</th><th style="min-width:60px;text-align:center">Score</th><th style="min-width:80px;text-align:center">Caminhos</th><th style="min-width:250px">Roles/RBAC</th></tr></thead><tbody>
$tblRisk
</tbody></table></div></div></div>

<!-- S4: EVIDENCE -->
<div class="sc"><div class="st">&#x1F6A8; 4. Evidencias de Alteracao RBAC<a href="$($portal.Audit)" target="_blank">Audit Log &#x2192;</a></div><div class="sb">
<div class="rt" style="padding:8px 14px"><b>$totalRbacChanges</b> alteracoes. <span style="color:#3fb950">&#x2795; add</span> <span style="color:#f85149">&#x274C; remove</span> <span style="color:#d29922">&#x270F;&#xFE0F; edit</span>$(if($dGrp.Count -gt 0){" | Grupos RBAC: <b>$($dGrp -join ', ')</b>"}) | <a href="$($portal.Audit)" target="_blank">Audit Log</a></div>
$(if($tblEvidence){"<div style='overflow-x:auto'><table style='min-width:850px'><thead><tr><th style='min-width:130px'>Quando</th><th style='min-width:150px'>Acao</th><th style='min-width:140px'>Quem Fez</th><th style='min-width:150px'>Role</th><th style='min-width:180px'>Alvo</th><th style='min-width:120px'>IP / Pais</th></tr></thead><tbody>$tblEvidence</tbody></table></div>"}else{"<div style='background:#21262d;border-radius:8px;padding:18px;text-align:center'><span style='color:#3fb950;font-size:16px'>&#x2705;</span><br><span style='color:#8b949e'>Nenhuma alteracao RBAC nos ultimos $DaysBack dias -- estabilidade nas permissoes.</span></div>"})
</div></div>

<!-- S5: ENTRA ID ROLES (complementar) -->
<div class="sc"><div class="st">&#x1F511; 5. Caminhos de Acesso ao Defender XDR<a href="$($portal.Entra)" target="_blank">Entra ID &#x2192;</a></div><div class="sb">
<div class="rt" style="padding:8px 14px"><b>$uniquePrincipals</b> principals, <b>$($accessPaths.Count)</b> caminhos. $nU users, $nG groups, $nS SPs.$(if($nS -gt 2){" &#x26A0;&#xFE0F; <b>$nS SPs privilegiados!</b>"}) Entra Roles + RBAC combinados. <a href="$($portal.Entra)" target="_blank">Entra</a> | <a href="$($portal.Perms)" target="_blank">RBAC</a></div>
<div style="max-height:500px;overflow:auto"><table style="min-width:850px"><thead><tr><th style="min-width:200px">Principal</th><th style="min-width:110px">Tipo</th><th style="min-width:110px">Risco</th><th style="min-width:200px">Role / RBAC</th><th style="min-width:200px">Caminho</th></tr></thead><tbody>
$tblAccess
</tbody></table></div></div></div>

<!-- S6: ARCHITECTURE SVG -->
<div class="sc"><div class="st">&#x1F5FA;&#xFE0F; 6. Arquitetura de Acesso RBAC<a href="$($portal.Perms)" target="_blank">Portal &#x2192;</a></div><div class="sb">
<div class="rt" style="padding:6px 14px;font-size:10px">Workloads &#x2192; XDR &#x2192; Roles/Grupos. <span style="color:#f85149">&#x25CF;</span> CRITICAL <span style="color:#3fb950">&#x25CF;</span> RBAC Group. Hover para detalhes.</div>
<svg viewBox="0 0 505 $svgH1" xmlns="http://www.w3.org/2000/svg" style="width:100%;background:#0d1117;border-radius:8px;border:1px solid #21262d">
<text x='68' y='42' fill='#6e7681' font-family='Segoe UI' font-size='6.5' text-anchor='middle' font-weight='600'>WORKLOADS</text>
<text x='242' y='42' fill='#58a6ff' font-family='Segoe UI' font-size='6.5' text-anchor='middle' font-weight='600'>PORTAL</text>
<text x='410' y='42' fill='#6e7681' font-family='Segoe UI' font-size='6.5' text-anchor='middle' font-weight='600'>ROLES / GRUPOS</text>
$svg1
</svg></div></div>

<!-- S7: EVENTS -->
<div class="sc"><div class="st">&#x1F50D; 7. Eventos que Alteram o RBAC ($DaysBack dias)<a href="$($portal.Hunt)" target="_blank">Hunting &#x2192;</a></div><div class="sb">
<div class="rt" style="padding:6px 14px;font-size:10px">Borda <span style="color:#f85149">&#x25CF;</span> = alto impacto (role/RBAC) | <span style="color:#d29922">&#x25CF;</span> = medio (grupo). Verifique: conta esperada? horario normal? IP conhecido?</div>
$(if($tblEv){"<div style='max-height:420px;overflow:auto'><table style='min-width:1000px'><thead><tr><th style='min-width:130px'>Timestamp</th><th style='min-width:120px'>Cenario</th><th style='min-width:160px'>Acao</th><th style='min-width:140px'>Quem Fez</th><th style='min-width:220px'>Detalhe</th><th style='min-width:120px'>Alvo</th><th style='min-width:130px'>IP / Pais</th></tr></thead><tbody>$tblEv</tbody></table></div>"}else{"<p style='color:#6e7681'>Nenhum evento nos ultimos $DaysBack dias.</p>"})
</div></div>

<!-- S8: VISUAL ANALYTICS -->
<div class="sc"><div class="st">&#x1F4CA; 8. Analise Visual</div><div class="sb">
<div class="gr">
<div>
<h4 style="color:#6e7681;font-size:11px;margin-bottom:8px">&#x1F4CA; Distribuicao por Cenario</h4>
<svg viewBox="0 0 520 200" xmlns="http://www.w3.org/2000/svg" style="width:100%;background:#0d1117;border-radius:8px;border:1px solid #21262d">$svgD</svg>
</div>
<div>
<h4 style="color:#6e7681;font-size:11px;margin-bottom:8px">&#x1F464; Top Atores</h4>
<svg viewBox="0 0 500 $aH" xmlns="http://www.w3.org/2000/svg" style="width:100%;background:#0d1117;border-radius:8px;border:1px solid #21262d">$svgA</svg>
</div>
</div>
<h4 style="color:#6e7681;font-size:11px;margin:14px 0 8px">&#x1F4C8; Timeline ($DaysBack dias)</h4>
<svg viewBox="0 0 780 210" xmlns="http://www.w3.org/2000/svg" style="width:100%;background:#0d1117;border-radius:8px;border:1px solid #21262d">$svgT</svg>
</div></div>

<!-- S9: DETECTION RULE -->
<div class="sc"><div class="st">&#x1F6A8; 9. Detection Rule -- Monitoramento Continuo do RBAC</div><div class="sb">
<div class="rt" style="padding:8px 14px">Query para <b>alerta automatico</b> no SOC.$(if($dGrp.Count -gt 0){" Grupos: <b>$($dGrp -join ', ')</b>."}) Crie a Detection Rule abaixo.</div>
<div class="ins"><h3>Passo a passo -- Detection Rule</h3><ol>
<li>Abrir <a href="$($portal.Hunt)" target="_blank" style="color:#58a6ff">Advanced Hunting</a></li>
<li>Copiar a query abaixo e colar no editor</li>
<li>Clicar em <b>Run query</b> para validar</li>
<li>Clicar em <b>Create detection rule</b></li>
<li>Nome: <code>Alteracao Permissoes Defender XDR</code> | Sev: <code>High</code> | Cat: <code>PrivilegeEscalation</code> | Freq: <code>1h</code></li>
<li>Em Actions: <b>Criar incidente</b></li>
<li>Ativar a rule e validar nos primeiros 24h</li></ol></div>
<button class="cp" onclick="navigator.clipboard.writeText(document.getElementById('k2').textContent).then(function(){var b=event.target;b.textContent='Copiado!';setTimeout(function(){b.textContent='Copiar'},2000)})">Copiar</button>
<div class="kql" id="k2">$kR</div>
<br style="clear:both"><br>
<details style="color:#6e7681;font-size:11px"><summary style="cursor:pointer;color:#58a6ff">&#x26A1; Query completa (sem filtros -- para investigacao)</summary>
<br><button class="cp" onclick="navigator.clipboard.writeText(document.getElementById('k1').textContent).then(function(){var b=event.target;b.textContent='Copiado!';setTimeout(function(){b.textContent='Copiar'},2000)})">Copiar</button>
<div class="kql" id="k1">$kH</div>
</details>
</div></div>

<!-- S10: RECOMMENDATIONS -->
<div class="sc"><div class="st">&#x1F4DD; 10. Recomendacoes (CIS / NIST / Microsoft PAR)</div><div class="sb">
<div class="rt" style="padding:8px 14px">Baseadas nos achados reais. Ref: <b>CIS Benchmark</b>, <b>NIST SP 800-53</b>, <b>Microsoft PAR</b>. Links diretos ao portal.</div>
<div style="overflow-x:auto"><table style="min-width:900px"><thead><tr><th style="min-width:80px">Severidade</th><th style="min-width:100px">Categoria</th><th style="min-width:200px">Achado</th><th style="min-width:280px">Recomendacao</th><th style="min-width:150px">Referencia</th></tr></thead><tbody>
$tblRecs
</tbody></table></div></div></div>

<!-- S11: TECHNICAL REFERENCES -->
<div class="sc"><div class="st">&#x1F4DA; 11. Informacoes Tecnicas</div><div class="sb">
<div class="rt" style="padding:8px 14px"><code>roleManagement/defender</code> (beta) + <code>roleManagement/directory</code> (v1.0) + <code>runHuntingQuery</code> (v1.0). <b>Somente leitura</b>.</div>
<div class="gr">
<div>
<h4 style="color:#6e7681;font-size:11px;margin-bottom:6px">Permissoes do Script</h4>
<table><thead><tr><th>Permissao</th><th>Finalidade</th></tr></thead><tbody>
<tr><td>Directory.Read.All</td><td>Ler grupos, usuarios, SPs</td></tr>
<tr><td>RoleManagement.Read.All</td><td>Ler roles (Entra + Defender RBAC)</td></tr>
<tr><td>ThreatHunting.Read.All</td><td>Executar KQL no Advanced Hunting</td></tr>
</tbody></table>
</div>
<div>
<h4 style="color:#6e7681;font-size:11px;margin-bottom:6px">Referencias Oficiais</h4>
<table><thead><tr><th>Tema</th><th>Link</th></tr></thead><tbody>
<tr><td>Unified RBAC</td><td><a href="https://learn.microsoft.com/defender-xdr/manage-rbac" target="_blank" style="color:#58a6ff">manage-rbac</a></td></tr>
<tr><td>Custom Roles</td><td><a href="https://learn.microsoft.com/defender-xdr/create-custom-rbac-roles" target="_blank" style="color:#58a6ff">create-roles</a></td></tr>
<tr><td>Permission Details</td><td><a href="https://learn.microsoft.com/defender-xdr/custom-permissions-details" target="_blank" style="color:#58a6ff">custom-permissions</a></td></tr>
<tr><td>XDR Auditing</td><td><a href="https://learn.microsoft.com/defender-xdr/microsoft-xdr-auditing" target="_blank" style="color:#58a6ff">xdr-auditing</a></td></tr>
<tr><td>Graph API</td><td><a href="https://learn.microsoft.com/graph/api/directoryaudit-list" target="_blank" style="color:#58a6ff">directoryaudit</a></td></tr>
<tr><td>CIS Benchmark</td><td><a href="https://www.cisecurity.org/benchmark/microsoft_365" target="_blank" style="color:#58a6ff">CIS M365</a></td></tr>
<tr><td>NIST AC Controls</td><td><a href="https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" target="_blank" style="color:#58a6ff">SP 800-53</a></td></tr>
</tbody></table>
</div>
</div>
<h4 style="color:#6e7681;font-size:11px;margin:14px 0 6px">Categorias de Permissao do Unified RBAC (Referencia)</h4>
<table><thead><tr><th>Categoria</th><th>Permissoes Incluidas</th><th>Descricao</th></tr></thead><tbody>
<tr><td style="color:#f85149;font-weight:600">&#x1F6E1;&#xFE0F; Security Operations</td><td class="sm">Security data basics, Alerts, Response, Live response (basic/advanced), File collection, Email quarantine, Email advanced actions</td><td>Operacoes SOC: view/manage incidents, alerts, investigations, response actions, advanced hunting, live response, email quarantine</td></tr>
<tr><td style="color:#d29922;font-weight:600">&#x1F4CA; Security Posture</td><td class="sm">Vulnerability management, Exception handling, Remediation handling, Application handling, Security baseline assessment, Exposure Management</td><td>Gestao de postura: TVM, baselines, Secure Score, exposure management, remediation tickets</td></tr>
<tr><td style="color:#58a6ff;font-weight:600">&#x2699;&#xFE0F; Authorization &amp; Settings</td><td class="sm">Authorization, Core security settings, Detection tuning, System settings</td><td>Configuracao: criar/editar roles, configurar deteccoes, definicoes do portal, alert tuning</td></tr>
<tr><td style="color:#3fb950;font-weight:600">&#x1F4BE; Data Operations</td><td class="sm">Data, Analytics Jobs Schedule</td><td>Dados: retencao, tiers, tabelas do Sentinel data lake, connectors, analytics jobs (Preview)</td></tr>
</tbody></table>
</div></div>

<!-- FOOTER -->
<div class="ft">
<div class="brand">&#x1F6E1;&#xFE0F; <a href="https://github.com/rfranca777/DefenderXDR-RBAC-Audit-v2" target="_blank">Defender XDR RBAC Audit v2.0</a></div>
<div class="brand" style="font-size:12px">Desenvolvido por <a href="https://github.com/rfranca777" target="_blank">Rafael Franca</a> | <a href="https://github.com/odefender" target="_blank">ODEFENDER</a></div>
<div class="sub">Ferramenta open-source para auditoria estado-da-arte de RBAC do Microsoft Defender XDR<br>MIT License | Gerado em $ts | PowerShell $($PSVersionTable.PSVersion) | Script v$scriptVersion</div>
</div>

</div></body></html>
"@

# =====================================================================
# 14. GRAVAR HTML (UTF-8 compativel PS 5.1 e 7)
# =====================================================================
[System.IO.File]::WriteAllText($reportFile, $htmlContent, [System.Text.Encoding]::UTF8)
Write-OK "Relatorio: $reportFile"

# Abrir no browser
Start-Process $reportFile

# =====================================================================
# SUMARIO FINAL
# =====================================================================
Write-Host "`n============================================" -ForegroundColor Green
Write-Host " AUDITORIA RBAC v$scriptVersion COMPLETA" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host " Workloads:       $aWL/4"
Write-Host " Custom Roles:    $($dR.value.Count)"
Write-Host " Entra Roles:     $tRA"
Write-Host " Grupos RBAC:     $($dGrp.Count)"
Write-Host " Risco CRITICAL:  $critCount"
Write-Host " Risco HIGH:      $highCount"
Write-Host " Evidencias:      $totalRbacChanges"
Write-Host " Eventos:         $tEv"
Write-Host " Recomendacoes:   $($recommendations.Count)"
Write-Host " Relatorio:       $reportFile"
Write-Host "============================================" -ForegroundColor Green
