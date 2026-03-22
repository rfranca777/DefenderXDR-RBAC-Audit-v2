<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell" alt="PowerShell">
  <img src="https://img.shields.io/badge/PowerShell-7%2B-blue?logo=powershell" alt="PowerShell 7">
  <img src="https://img.shields.io/badge/Microsoft%20Graph-SDK-orange?logo=microsoft" alt="Graph SDK">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT">
  <img src="https://img.shields.io/badge/Defender%20XDR-Unified%20RBAC-purple?logo=microsoft" alt="Defender XDR">
  <img src="https://img.shields.io/badge/Version-2.0.0-brightgreen" alt="v2.0.0">
</p>

<h1 align="center">🛡️ Defender XDR RBAC Audit v2.0</h1>

<p align="center">
  <strong>Auditoria estado-da-arte de RBAC do Microsoft Defender XDR</strong><br>
  Mapeia custom roles, categorias de permissão, risco por principal, evidências e recomendações CIS/NIST
</p>

<p align="center">
  <a href="https://github.com/rfranca777">rfranca777</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#whats-new">What's New</a> •
  <a href="#report-sections">Report Sections</a>
</p>

---

## 🆕 What's New in v2.0

| # | Melhoria | Descrição |
|---|---|---|
| 1 | **Permission Categories Matrix** | Mapeia as 4 categorias do RBAC (SecOps, Posture, Auth/Settings, DataOps) por role |
| 2 | **Risk Analysis** | Classifica cada principal por nível de risco (CRITICAL/HIGH/MEDIUM/LOW) com score |
| 3 | **KQL Improvements** | Extração de Detail e IP via `coalesce` — colunas nunca mais vazias |
| 4 | **CIS/NIST Recommendations** | Recomendações dinâmicas baseadas nos achados reais, com referência a CIS Benchmark e NIST SP 800-53 |
| 5 | **Clickable Paths** | Links diretos ao portal para cada caminho de acesso (Entra Roles e RBAC) |
| 6 | **Per-Graph Rationale** | Cada gráfico (donut, timeline, top actors) tem racional técnico individual |
| 7 | **SVG Redesign** | Cores por risco, badges de permissão, tooltips detalhados |
| 8 | **Portal Deep Links** | Links para Secure Score, Incidents, PIM, Access Reviews, cada workload |
| 9 | **CSS Uniformity** | Segoe UI em tudo, border-radius consistente, scroll horizontal em todas as tabelas |
| 10 | **11 Report Sections** | De 8 para 11 seções, todas com foco RBAC |

## 🎯 O Problema

> *"Quem criou ou alterou perfis de acesso no portal do Defender XDR? E como classificar o risco de cada usuário com acesso?"*

O acesso ao Microsoft Defender XDR é controlado por **múltiplas fontes**:

| Caminho de Acesso | Como funciona | Risco se não monitorado |
|---|---|---|
| **Entra ID Roles** | Usuário recebe "Security Administrator" diretamente | Escalação de privilégio |
| **Grupos de Segurança** | Usuário é adicionado a grupo com RBAC associado | Acesso indireto não rastreado |
| **Unified RBAC Custom Roles** | Admin cria role com permissões granulares | Shadow admin não visível |
| **Grupos AD on-prem** | Grupo sincronizado via Entra Connect | Bypass do controle cloud |

## 🚀 Quick Start

```powershell
# 1. Clonar
git clone https://github.com/rfranca777/DefenderXDR-RBAC-Audit-v2.git
cd DefenderXDR-RBAC-Audit-v2

# 2. Executar (módulos serão instalados automaticamente se necessário)
.\Audit-DefenderXDR-RBAC.ps1

# 3. O relatório HTML abre automaticamente no browser
```

### Pré-requisitos

- PowerShell 5.1+ ou PowerShell 7+
- Microsoft Graph PowerShell SDK (instalado automaticamente)
- Permissões Graph: `Directory.Read.All`, `RoleManagement.Read.All`, `ThreatHunting.Read.All`

## 📊 Report Sections (11)

| # | Seção | Descrição |
|---|---|---|
| 1 | **RBAC Custom Roles** | Foco principal — custom roles, assignments, membros efetivos |
| 2 | **Permission Categories** | Matriz 4 categorias: SecOps, Posture, Auth/Settings, DataOps |
| 3 | **Risk Analysis** | Classificação CRITICAL/HIGH/MEDIUM/LOW por principal |
| 4 | **Evidence** | Quem alterou RBAC — com IP e país |
| 5 | **Access Paths** | Todos os caminhos de acesso (Entra + RBAC) com links |
| 6 | **Architecture SVG** | Diagrama interativo workloads ↔ XDR ↔ roles |
| 7 | **Events** | Eventos do Advanced Hunting com Detail e IP |
| 8 | **Visual Analytics** | Donut, timeline, top actors — cada um com racional |
| 9 | **Detection Rule** | KQL pronta para criar alerta automático no SOC |
| 10 | **Recommendations** | CIS Benchmark, NIST SP 800-53, Microsoft PAR |
| 11 | **Technical References** | APIs, permissões, documentação oficial, categorias RBAC |

## 🔐 Permission Categories (Unified RBAC)

| Categoria | Permissões | Impacto |
|---|---|---|
| 🛡️ **Security Operations** | Incidents, alerts, response, live response, hunting, email | **Mais alto** — controle operacional do SOC |
| 📊 **Security Posture** | TVM, baselines, Secure Score, exposure management | **Alto** — visibilidade de vulnerabilidades |
| ⚙️ **Authorization & Settings** | Roles, system settings, detection tuning | **Crítico** — auto-elevação possível |
| 💾 **Data Operations** | Data retention, Sentinel data lake, analytics | **Médio** — acesso a dados sensíveis |

## 📋 Data Sources

| Dado | Fonte | API |
|---|---|---|
| Custom roles RBAC | `roleManagement/defender/roleDefinitions` | Graph beta |
| RBAC assignments | `roleManagement/defender/roleAssignments` | Graph beta |
| Entra ID Roles | `roleManagement/directory` | Graph v1.0 |
| Principals | `directoryObjects` | Graph v1.0 |
| Group members | `groups/{id}/members` | Graph v1.0 |
| Alteração de permissões | `CloudAppEvents` | KQL |
| Alteração de grupo AD | `IdentityDirectoryEvents` | KQL |
| Workloads ativos | `DeviceInfo`, `EmailEvents`, etc. | KQL |

## 📖 References

- [Unified RBAC](https://learn.microsoft.com/defender-xdr/manage-rbac)
- [Custom Permissions Details](https://learn.microsoft.com/defender-xdr/custom-permissions-details)
- [Create Custom RBAC Roles](https://learn.microsoft.com/defender-xdr/create-custom-rbac-roles)
- [XDR Auditing](https://learn.microsoft.com/defender-xdr/microsoft-xdr-auditing)
- [CIS Benchmark for Microsoft 365](https://www.cisecurity.org/benchmark/microsoft_365)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

## 📄 License

MIT License — see [LICENSE](LICENSE)

## 👤 Author

**Rafael Franca** — [ODEFENDER](https://github.com/odefender) | [rfranca777](https://github.com/rfranca777)
