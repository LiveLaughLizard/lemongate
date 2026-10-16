# LemonGate Helm chart

Deploys LemonGate, the self-hosted AI gateway and admin console for vLLM, to Kubernetes.

## Prerequisites

- Kubernetes 1.25+ and Helm 3.8+
- A LemonGate container image in a registry your cluster can pull from. No image is
  published yet, so build and push one from the repository root:

  ```bash
  docker build --build-arg VERSION=0.1.0 -t ghcr.io/<you>/lemongate:0.1.0 .
  docker push ghcr.io/<you>/lemongate:0.1.0
  ```

- Postgres 14+ (external), or enable the bundled single-instance Postgres for evaluation.

## Install

Generate the bootstrap secrets once and keep them. `secretKey` encrypts stored credentials,
so changing it later makes those credentials unreadable.

```bash
kubectl create namespace lemongate
kubectl -n lemongate create secret generic lemongate-secrets \
  --from-literal=master-key="$(openssl rand -hex 24)" \
  --from-literal=secret-key="$(openssl rand -hex 32)"
```

**Evaluation**, with the bundled Postgres:

```bash
helm install lemongate deploy/helm/lemongate -n lemongate \
  --set image.repository=ghcr.io/<you>/lemongate \
  --set secrets.existingSecret=lemongate-secrets \
  --set postgresql.enabled=true \
  --set postgresql.auth.password="$(openssl rand -hex 16)"
```

**Production**, with an external database and an ingress:

```bash
kubectl -n lemongate create secret generic lemongate-db \
  --from-literal=database-url='postgres://lemongate:...@db.internal:5432/lemongate?sslmode=require'

helm install lemongate deploy/helm/lemongate -n lemongate -f my-values.yaml
```

```yaml
# my-values.yaml
image:
  repository: ghcr.io/<you>/lemongate
secrets:
  existingSecret: lemongate-secrets
database:
  existingSecret: lemongate-db
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "600"
    nginx.ingress.kubernetes.io/proxy-body-size: "64m"
  hosts:
    - host: ai.example.com
      paths: [{ path: /, pathType: Prefix }]
  tls:
    - secretName: ai-example-com-tls
      hosts: [ai.example.com]
config:
  models:
    - name: llama-3.1-8b
      api_base: http://vllm-llama.vllm.svc:8000/v1
      upstream_model: meta-llama/Llama-3.1-8B-Instruct
      api_key: ${VLLM_API_KEY:-}
      input_cost_per_m: 0.10
      output_cost_per_m: 0.20
extraEnv:
  - name: VLLM_API_KEY
    valueFrom:
      secretKeyRef: { name: vllm, key: api-key }
```

Check the release with `helm test lemongate -n lemongate`, then open the console. The
install notes print the URL and the command that reveals the master key.

## Secrets

You can supply secrets in two ways:

- **`secrets.existingSecret`** (recommended): a Secret you manage with these keys:

  | Key | Required | Used for |
  |---|---|---|
  | `master-key` | yes | Admin credential (at least 16 characters) |
  | `secret-key` | yes | Encryption of stored credentials. Keep it stable |
  | `oidc-client-secret` | with OIDC | OIDC client secret |
  | `smtp-password` | with SMTP auth | SMTP password |
  | `metrics-token` | no | Bearer token required to scrape `/metrics` |

- **Inline values**: `secrets.masterKey`, `secrets.secretKey`, `oidc.clientSecret`,
  `smtp.password` and `metrics.token`. The chart renders them into its own Secret. They are
  then stored in the Helm release, so use this option only for testing.

The database URL comes from `database.existingSecret` (key `database-url` by default),
`database.url`, or the bundled Postgres. Exactly one of the three must be configured.

## Values

| Key | Default | Description |
|---|---|---|
| `image.repository` / `tag` / `pullPolicy` | `ghcr.io/livelaughlizard/lemongate` / appVersion / `IfNotPresent` | Container image |
| `replicaCount` | `1` | Rate limits, cache and cooldowns are kept in memory per replica |
| `baseURL` | derived from ingress | Public URL. Cookies are marked Secure when it is `https://` |
| `secrets.*` | | See [Secrets](#secrets) |
| `database.url` / `existingSecret` / `existingSecretKey` | | External Postgres |
| `config` | `{}` | LemonGate YAML config (models, aliases, fallbacks, access groups, settings) |
| `sessionHours` | `12` | Console session lifetime |
| `debug` | `false` | Debug logging |
| `oidc.*` | disabled | OIDC SSO. The redirect URI is `<baseURL>/ui/sso/callback` |
| `oidc.trustEmail` | `false` | Link existing accounts by email even without `email_verified` |
| `smtp.*` | disabled | Email alert channel |
| `metrics.token` | `""` | Static scrape token |
| `metrics.serviceMonitor.enabled` / `useToken` | `false` | Prometheus Operator ServiceMonitor |
| `extraEnv` / `extraEnvFrom` | `[]` | Extra environment, e.g. upstream API keys used as `${VAR}` in `config` |
| `service.type` / `port` | `ClusterIP` / `4000` | Service |
| `ingress.*` | disabled | Ingress. Turn proxy buffering off for streaming |
| `resources` | 100m / 256Mi request, 1Gi limit | Gateway resources |
| `podSecurityContext` / `securityContext` | non-root, read-only root FS, no capabilities | Hardened by default |
| `tmpVolume.sizeLimit` | `256Mi` | Scratch space for multipart uploads |
| `startupProbe` / `livenessProbe` / `readinessProbe` | `/health/live`, `/health/ready` | Probes |
| `terminationGracePeriodSeconds` | `45` | The server drains for up to 30s |
| `podDisruptionBudget.enabled` | `false` | PDB (blocks node drains when `replicaCount` is 1) |
| `networkPolicy.enabled` / `ingressFrom` | `false` / all | Restrict ingress to the gateway, and to Postgres from the gateway only |
| `postgresql.enabled` | `false` | Bundled single-instance Postgres (no HA, no backups) |
| `postgresql.auth.password` / `existingSecret` | | Letters and digits only |
| `postgresql.persistence.size` / `storageClass` | `10Gi` / default | Data volume |
| `nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints`, `extraVolumes`, `extraVolumeMounts`, `podAnnotations`, `podLabels`, `imagePullSecrets` | | Standard scheduling and pod options |

## Operational notes

- **Migrations** run automatically when the pod starts. They are serialized with a Postgres
  advisory lock, so rolling updates are safe.
- **Config changes** to `config` or the chart Secret roll the pods automatically through
  checksum annotations. Changes to a Secret you manage need
  `kubectl rollout restart deploy/<release>-lemongate`.
- **Scaling.** Spend, budgets, keys and settings live in Postgres, so extra replicas serve
  traffic correctly. However, each replica enforces rpm/tpm/parallel limits and keeps its own
  cache and cooldowns.
- **Back up the database.** It holds keys, spend history, request logs and the audit log.
