# Microsoft Foundry GitHub OIDC Setup Guide

This guide covers the one-time Azure setup that lets the
`.github/workflows/security-triage.yml` daily analysis workflow authenticate to
Microsoft Foundry / Azure OpenAI **without a stored client secret**, using
GitHub Actions OpenID Connect (OIDC) federation and a branch-bound Microsoft
Entra ID app registration.

This is a documentation-and-workflow-YAML change only. Nothing in this
repository provisions, modifies, or queries Azure resources on its own. Every
command below is meant to be copy/pasted and run **by a human operator** with
appropriate Azure and GitHub permissions, after reading and adapting the
placeholders to your environment.

> Scope note: this guide is written for the battle-test configuration where
> the analyzed repository, the review repository, and the workflow-hosting
> repository are all `flatcar/security-triage`. Moving the workflow to
> `flatcar/Flatcar` later only changes the federated credential subject, the
> repository/organization variables, and the `SECURITY_TRIAGE_ADVISORY_REPO`
> / `SECURITY_TRIAGE_REVIEW_REPO` values -- never the Python business logic.

## How this fits together

1. GitHub Actions requests a short-lived, workflow-scoped OIDC token from
   `https://token.actions.githubusercontent.com` (this happens automatically;
   no configuration is needed on the GitHub side beyond `permissions:
   id-token: write`).
2. `azure/login@v2` exchanges that OIDC token for an Azure AD access token,
   using a **federated identity credential** configured on an Entra app
   registration -- no client secret is created or stored anywhere.
3. The workflow then asks Azure CLI for a second, narrowly-scoped access token
   for the `https://cognitiveservices.azure.com/` resource and passes it to
   `security-triage discovery`/`cleanup` as `FOUNDRY_BEARER_TOKEN`.
4. The Python client only ever makes an HTTPS chat-completions request with
   that bearer token; it never shells out to Azure CLI at runtime (see
   `.github/copilot-instructions.md`).

The current implementation calls the Azure OpenAI-compatible chat-completions
data plane (`/openai/deployments/.../chat/completions` or `/openai/v1/chat/completions`),
so the service principal needs the **`Cognitive Services OpenAI User`** role,
scoped to the specific account referenced by `FOUNDRY_ENDPOINT` -- nothing
broader. If the implementation later moves to Foundry project/agent APIs,
re-evaluate the required role (for example project-scoped `Azure AI User`
/ `Foundry User`-style roles) instead of preemptively broadening this one.

Authoritative references:

- GitHub: [Configuring OpenID Connect in Azure](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-azure)
- GitHub: [About security hardening with OpenID Connect](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- Microsoft Learn: [Connect GitHub Actions to Azure using OpenID Connect](https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure)
- Microsoft Entra: [Configure an app to trust a GitHub repository](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust-github)
- Azure RBAC built-in roles (Cognitive Services / AI): [Azure built-in roles for AI services](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/ai-machine-learning)
- Action used in the workflow: [`azure/login`](https://github.com/Azure/login)

---

## Path A: Azure Portal

1. **Create or choose a single-tenant Microsoft Entra app registration.**
   In the Azure Portal, go to **Microsoft Entra ID > App registrations > New
   registration**. Choose **Accounts in this organizational directory only
   (Single tenant)**. This creates both the app registration and its backing
   service principal. Record the **Application (client) ID**, **Directory
   (tenant) ID**, and your **Subscription ID** -- these become GitHub
   variables, never secrets.

2. **Add a federated credential for GitHub Actions.**
   Open the app registration, go to **Certificates & secrets > Federated
   credentials > Add credential**, and choose the **GitHub Actions deploying
   Azure resources** scenario (or **Other issuer** if that scenario is
   unavailable in your tenant).

3. **Configure the exact issuer, audience, and subject.**
   - Issuer: `https://token.actions.githubusercontent.com`
   - Audience: `api://AzureADTokenExchange`
   - Subject identifier (branch-bound, matches this workflow's trigger
     branch): `repo:flatcar/security-triage:ref:refs/heads/<default-branch>`

   Replace `<default-branch>` with the actual default branch name (for
   example `main`). The subject is an **exact string match** -- see
   [Troubleshooting](#validation-troubleshooting-and-safe-testing) below for
   what happens if it does not match exactly.

4. **Assign the least-privilege role on the specific Foundry/Azure OpenAI
   account.** Navigate to the exact Azure OpenAI / Cognitive Services
   resource referenced by your intended `FOUNDRY_ENDPOINT` (**not** the
   subscription or resource group), open **Access control (IAM) > Add role
   assignment**, and assign **`Cognitive Services OpenAI User`** to the app
   registration's service principal. Scoping the role to the individual
   resource (rather than the resource group or subscription) keeps this the
   minimum privilege needed to call chat completions.

5. **Add the non-secret IDs and Foundry settings as GitHub variables.**
   In the GitHub repository (or organization) settings, under **Settings >
   Secrets and variables > Actions > Variables**, add:

   | Variable | Example value | Notes |
   | --- | --- | --- |
   | `AZURE_CLIENT_ID` | `11111111-2222-3333-4444-555555555555` | App registration's client ID |
   | `AZURE_TENANT_ID` | `66666666-7777-8888-9999-000000000000` | Directory (tenant) ID |
   | `AZURE_SUBSCRIPTION_ID` | `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee` | Subscription containing the Foundry/Azure OpenAI resource |
   | `FOUNDRY_ENDPOINT` | `https://<resource>.cognitiveservices.azure.com` | Base endpoint only, no path |
   | `FOUNDRY_DEPLOYMENT` | `gpt-5.4` | Reasoning/cleanup deployment name |
   | `FOUNDRY_EXTRACTION_DEPLOYMENT` | `gpt-5.4-mini` | First-pass extraction deployment name |
   | `FOUNDRY_API_VERSION` | `2024-06-01` or `v1` | Dated value for legacy endpoints, `v1`/`preview` for OpenAI v1/project endpoints |

   These are all **repository or organization variables** (`vars.*`), not
   secrets: none of them, on their own, grants access to anything without the
   federated trust relationship configured in steps 2-3.

6. **No client secret is created or stored anywhere in this flow.** If a
   wizard in the Portal offers to create a client secret, decline it; this
   design intentionally never needs one.

---

## Path B: Azure CLI

Run these as an operator who is already `az login`-authenticated and has
permission to create app registrations, federated credentials, and role
assignments (see
[Required Entra and Azure RBAC permissions](#required-entra-and-azure-rbac-permissions)
below). None of these commands are executed by this repository's automation;
they are provided for you to run manually, once, outside of CI.

### 1. Select the subscription and record tenant/subscription IDs

```bash
az account set --subscription "<subscription-name-or-id>"
AZURE_TENANT_ID=$(az account show --query tenantId -o tsv)
AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
echo "AZURE_TENANT_ID=$AZURE_TENANT_ID"
echo "AZURE_SUBSCRIPTION_ID=$AZURE_SUBSCRIPTION_ID"
```

### 2. Create the app registration and service principal

```bash
APP_NAME="security-triage-github-oidc"
APP_ID=$(az ad app create --display-name "$APP_NAME" --sign-in-audience AzureADMyOrg --query appId -o tsv)
az ad sp create --id "$APP_ID" >/dev/null
echo "AZURE_CLIENT_ID=$APP_ID"
```

### 3. Create the branch-subject federated identity credential

Write the credential parameters to a JSON file rather than passing the
subject inline, so the exact-match subject string cannot be mangled by shell
quoting:

```bash
DEFAULT_BRANCH="main"   # replace with the repository's actual default branch
cat > federated-credential.json <<EOF
{
  "name": "security-triage-default-branch",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:flatcar/security-triage:ref:refs/heads/${DEFAULT_BRANCH}",
  "audiences": ["api://AzureADTokenExchange"],
  "description": "GitHub Actions OIDC trust for the security-triage daily analysis workflow (default branch only)"
}
EOF

az ad app federated-credential create \
  --id "$APP_ID" \
  --parameters federated-credential.json

rm federated-credential.json
```

### 4. Resolve the Cognitive Services / Azure OpenAI account resource ID

```bash
FOUNDRY_RESOURCE_GROUP="<resource-group-name>"
FOUNDRY_ACCOUNT_NAME="<cognitive-services-account-name>"
FOUNDRY_ACCOUNT_ID=$(az cognitiveservices account show \
  --resource-group "$FOUNDRY_RESOURCE_GROUP" \
  --name "$FOUNDRY_ACCOUNT_NAME" \
  --query id -o tsv)
echo "FOUNDRY_ACCOUNT_ID=$FOUNDRY_ACCOUNT_ID"
```

### 5. Assign `Cognitive Services OpenAI User` at that exact scope

```bash
SP_OBJECT_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv)

az role assignment create \
  --assignee-object-id "$SP_OBJECT_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Cognitive Services OpenAI User" \
  --scope "$FOUNDRY_ACCOUNT_ID"
```

Scoping `--scope` to the single Cognitive Services account (not the resource
group or subscription) is the least-privilege choice: the service principal
can call chat completions on this one account and nothing else.

### 6. Print only the non-secret GitHub variable values

```bash
echo "AZURE_CLIENT_ID=$APP_ID"
echo "AZURE_TENANT_ID=$AZURE_TENANT_ID"
echo "AZURE_SUBSCRIPTION_ID=$AZURE_SUBSCRIPTION_ID"
echo "FOUNDRY_ENDPOINT=https://${FOUNDRY_ACCOUNT_NAME}.cognitiveservices.azure.com"
```

Set these (plus `FOUNDRY_DEPLOYMENT`, `FOUNDRY_EXTRACTION_DEPLOYMENT`, and
`FOUNDRY_API_VERSION`) as GitHub Actions **variables**, exactly as in the
Portal path's table above. No client secret is ever printed or stored because
none was created.

### 7. Validate the federated credential and role assignment (no secret issued)

```bash
az ad app federated-credential list --id "$APP_ID" -o table

az role assignment list \
  --assignee "$SP_OBJECT_ID" \
  --scope "$FOUNDRY_ACCOUNT_ID" \
  -o table
```

Confirm the federated credential's `subject` exactly matches
`repo:flatcar/security-triage:ref:refs/heads/<default-branch>` and that the
role assignment shows `Cognitive Services OpenAI User` at the Cognitive
Services account scope.

### Teardown

```bash
az role assignment delete \
  --assignee "$SP_OBJECT_ID" \
  --role "Cognitive Services OpenAI User" \
  --scope "$FOUNDRY_ACCOUNT_ID"

az ad app federated-credential delete \
  --id "$APP_ID" \
  --federated-credential-id "security-triage-default-branch"

az ad app delete --id "$APP_ID"
```

Deleting the app registration also removes its service principal and any
remaining federated credentials/role assignments tied to it.

### Required Entra and Azure RBAC permissions

The operator running the commands above needs, at minimum:

- Entra ID: permission to create app registrations and manage federated
  credentials on them (for example the built-in **Application Administrator**
  or **Cloud Application Administrator** Entra role, or ownership of the
  specific app registration for the federated-credential step only).
- Azure RBAC: **Owner** or **User Access Administrator** (or an equivalent
  custom role including `Microsoft.Authorization/roleAssignments/write`) at
  the Cognitive Services account scope, to create the role assignment in
  step 5.

Neither permission is required by, or granted to, the GitHub Actions workflow
itself -- they are one-time, human-operator setup steps.

---

## GitHub configuration

- The daily workflow (`.github/workflows/security-triage.yml`) declares:
  ```yaml
  permissions:
    contents: read
    issues: write
    id-token: write
  ```
  `id-token: write` is what allows the workflow to request an OIDC token at
  all; without it, `azure/login` fails immediately with a token-request
  error.
- `azure/login@v2` is called with `client-id`, `tenant-id`, and
  `subscription-id` inputs only -- no `client-secret` input, because none
  exists.
- Repository or organization **variables** (not secrets) hold
  `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`,
  `FOUNDRY_ENDPOINT`, `FOUNDRY_DEPLOYMENT`, `FOUNDRY_EXTRACTION_DEPLOYMENT`,
  and `FOUNDRY_API_VERSION`. None of these values are secret by themselves:
  the trust boundary is the federated credential's issuer/audience/subject
  match, not knowledge of the client ID.
- `SECURITY_TRIAGE_ADVISORY_REPO` and `SECURITY_TRIAGE_REVIEW_REPO` are set to
  `${{ github.repository }}` at the workflow level, so the same YAML works
  unmodified after a repository move; only the federated credential subject
  (tied to `flatcar/security-triage`) needs to be re-created for the new
  repository during that future migration.

## Why client/tenant/subscription IDs can be variables, not secrets

Knowing an app registration's client ID, tenant ID, or subscription ID does
not, by itself, grant any access. An attacker would also need to satisfy the
federated credential's exact issuer/audience/subject match -- which requires
controlling a GitHub Actions run on the specific branch of the specific
repository named in the subject. Treating these IDs as secrets would only add
operational friction (secret rotation, masked-log noise) without a real
security benefit.

---

## Validation, troubleshooting, and safe testing

### Branch-subject exact-match behavior

The federated credential's `subject` must match the **exact** string GitHub
sends in the OIDC token's `sub` claim for that workflow run, for example
`repo:flatcar/security-triage:ref:refs/heads/main`. Common causes of a
mismatch:

- **Renaming the default branch** (for example `main` to `master` or vice
  versa) without updating the federated credential's subject -- `azure/login`
  will fail with an AADSTS70021-style "no matching federated identity record
  found" error.
- Running the workflow from a **different branch, tag, pull request, or
  environment** than the one encoded in the subject. This workflow only
  triggers on `schedule` and `workflow_dispatch` from the default branch, so
  it will only ever present the subject configured above -- but a
  `workflow_dispatch` run manually started from a non-default branch will
  fail to authenticate, which is expected and desirable (fail closed).

### Audience/issuer/subject mismatch symptoms

- Wrong audience (`aud` claim) -- error mentions `AADSTS700021` /
  "unauthorized_client" or a federated credential not found for the presented
  token; verify `audiences` is exactly `["api://AzureADTokenExchange"]`.
- Wrong issuer -- effectively unreachable in normal use since GitHub always
  presents `https://token.actions.githubusercontent.com`; a custom OIDC
  proxy or self-hosted runner misconfiguration would be the only way to see
  this.
- Wrong subject -- the most common failure; recheck repository name casing,
  branch name, and the `ref:refs/heads/<branch>` prefix (as opposed to
  `ref:refs/tags/<tag>` or `environment:<name>`, which use different subject
  formats).

### Missing `id-token: write`

If the workflow's `permissions:` block omits `id-token: write` (or an
organization-level policy forces it to `none`), the `id-token` request step
inside `azure/login` fails before it ever reaches Azure, typically with a
message about being unable to get an OIDC token / missing permissions.

### Wrong account scope

If the role assignment was made at the wrong Cognitive Services account (or
at the resource group/subscription instead of the account), calls may still
succeed against a *different* account than `FOUNDRY_ENDPOINT` points to (if a
broader scope was used) or fail with `401`/`403` (if the intended account
never received the assignment). Always verify the assignment's `--scope`
matches `FOUNDRY_ACCOUNT_ID` for the exact account in `FOUNDRY_ENDPOINT`.

### Role-propagation delay

Azure RBAC role assignments can take several minutes to propagate. If a
freshly assigned `Cognitive Services OpenAI User` role produces `403
Forbidden` immediately after creation, wait a few minutes and retry (a manual
`workflow_dispatch` run is the safe way to retry -- see below) before
assuming the assignment is wrong.

### Incorrect endpoint/deployment/API version

- `FOUNDRY_ENDPOINT` must be the base resource URL only (no trailing path);
  the client appends the deployment-specific path.
- `FOUNDRY_DEPLOYMENT` / `FOUNDRY_EXTRACTION_DEPLOYMENT` must match deployment
  names that actually exist on that resource (Azure OpenAI deployment names
  are resource-specific, not global model names).
- `FOUNDRY_API_VERSION` must match the endpoint family: a dated version (for
  example `2024-06-01`) for legacy `/openai/deployments/...` endpoints, or
  `v1`/`preview` for OpenAI v1 / Foundry project endpoints. See `README.md`
  for the two supported endpoint families.

### Cognitive Services token audience failures

The workflow explicitly requests a token for the
`https://cognitiveservices.azure.com/` resource
(`az account get-access-token --resource https://cognitiveservices.azure.com/`).
Requesting a token for the wrong resource (for example the default Azure
Resource Manager audience) produces a bearer token that Azure OpenAI's data
plane will reject with `401 Unauthorized`, since the token's audience claim
will not match what the Cognitive Services endpoint expects.

### Safe manual `workflow_dispatch` smoke test

Before relying on the schedule, validate the whole chain manually:

1. In the GitHub UI, go to **Actions > Flatcar Security Triage > Run
   workflow** and dispatch it manually from the default branch.
2. Watch the **Azure login (OIDC)** and **Obtain Microsoft Foundry access
   token** steps succeed (the token value itself is masked in logs via
   `::add-mask::`).
3. Confirm the **Discovery** and **Cleanup** steps complete and upload
   `reports/discovery.json` / `reports/cleanup.json` as workflow artifacts.
4. Confirm the **Create review issue(s)** step creates (or, on a repeat
   dispatch, idempotently reuses) a `security-triage/review`-labeled issue in
   this repository -- never in `flatcar/Flatcar`.
5. To inspect what Azure saw, check **Microsoft Entra ID > Sign-in logs**
   (filter by the app registration/service principal) and, for the role
   assignment itself, **Cognitive Services account > Activity log**, for the
   corresponding timestamp.

### Fork and pull-request protections

This workflow never triggers on `pull_request` (only `schedule` and
`workflow_dispatch` from the default branch), so a fork's pull request can
never present a matching OIDC subject and can never obtain
`FOUNDRY_BEARER_TOKEN`, `AZURE_CLIENT_ID`, or repository/organization
variables through this path. Do not add a `pull_request` trigger to this
workflow, and do not widen the federated credential's subject to a wildcard
branch pattern.

### Same-repository `GITHUB_TOKEN` limitation and the future GitHub App option

The daily workflow's `GITHUB_TOKEN` is scoped to the repository the workflow
runs in. Because `SECURITY_TRIAGE_ADVISORY_REPO` and
`SECURITY_TRIAGE_REVIEW_REPO` are both this repository during battle testing,
`GITHUB_TOKEN` is sufficient for every mutation this pipeline performs today.

If a future rollout keeps the workflow running from `flatcar/security-triage`
while the advisory issues live in a *different* repository (for example
`flatcar/Flatcar`), `GITHUB_TOKEN` alone will not work: a same-repository
Actions token cannot write to another repository. That configuration would
instead require a narrowly scoped **GitHub App installation token** (or
equivalent), installed only on the target advisory repository with `issues:
write` permission, exchanged for a short-lived installation token at the
start of the relevant job. This repository's Python interfaces already
accept the advisory and review repositories independently
(`--advisory-repo` / `--review-repo`, or `SECURITY_TRIAGE_ADVISORY_REPO` /
`SECURITY_TRIAGE_REVIEW_REPO`) so only the token-acquisition step of the
workflow would need to change, not the underlying CLI or Python logic. The
simplest and currently supported path remains running the workflow directly
inside the same repository that owns the advisory issues.
