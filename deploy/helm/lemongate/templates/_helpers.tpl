{{- define "lemongate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lemongate.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "lemongate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lemongate.labels" -}}
helm.sh/chart: {{ include "lemongate.chart" . }}
{{ include "lemongate.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "lemongate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lemongate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
{{- end }}

{{- define "lemongate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "lemongate.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "lemongate.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/* Secret holding the bootstrap keys and optional OIDC/SMTP/metrics secrets. */}}
{{- define "lemongate.secretName" -}}
{{- default (include "lemongate.fullname" .) .Values.secrets.existingSecret }}
{{- end }}

{{/* Public base URL: explicit value, else derived from the first ingress host. */}}
{{- define "lemongate.baseURL" -}}
{{- if .Values.baseURL }}
{{- .Values.baseURL | trimSuffix "/" }}
{{- else if and .Values.ingress.enabled .Values.ingress.hosts }}
{{- $host := (index .Values.ingress.hosts 0).host }}
{{- printf "%s://%s" (ternary "https" "http" (gt (len .Values.ingress.tls) 0)) $host }}
{{- end }}
{{- end }}

{{/* Bundled Postgres. */}}
{{- define "lemongate.postgresql.fullname" -}}
{{- printf "%s-postgresql" (include "lemongate.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lemongate.postgresql.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lemongate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgresql
{{- end }}

{{- define "lemongate.postgresql.secretName" -}}
{{- default (include "lemongate.postgresql.fullname" .) .Values.postgresql.auth.existingSecret }}
{{- end }}

{{- define "lemongate.postgresql.secretKey" -}}
{{- if .Values.postgresql.auth.existingSecret }}
{{- .Values.postgresql.auth.existingSecretKey }}
{{- else }}
{{- "password" }}
{{- end }}
{{- end }}

{{/* Fail early on incomplete configuration. */}}
{{- define "lemongate.validate" -}}
{{- if not .Values.secrets.existingSecret }}
{{- $_ := required "secrets.masterKey is required (or set secrets.existingSecret)" .Values.secrets.masterKey }}
{{- $_ := required "secrets.secretKey is required (or set secrets.existingSecret)" .Values.secrets.secretKey }}
{{- if lt (len .Values.secrets.masterKey) 16 }}
{{- fail "secrets.masterKey must be at least 16 characters (generate one with `openssl rand -hex 24`)" }}
{{- end }}
{{- end }}
{{- $dbSources := 0 }}
{{- if .Values.postgresql.enabled }}{{ $dbSources = add1 $dbSources }}{{ end }}
{{- if .Values.database.url }}{{ $dbSources = add1 $dbSources }}{{ end }}
{{- if .Values.database.existingSecret }}{{ $dbSources = add1 $dbSources }}{{ end }}
{{- if ne (int $dbSources) 1 }}
{{- fail "configure exactly one database source: postgresql.enabled, database.url or database.existingSecret" }}
{{- end }}
{{- if and .Values.postgresql.enabled (not .Values.postgresql.auth.existingSecret) }}
{{- $pw := required "postgresql.auth.password is required (or set postgresql.auth.existingSecret)" .Values.postgresql.auth.password }}
{{- if not (regexMatch "^[A-Za-z0-9]+$" $pw) }}
{{- fail "postgresql.auth.password must contain only letters and digits (it is embedded in the connection URL)" }}
{{- end }}
{{- end }}
{{- if and .Values.oidc.enabled (or (not .Values.oidc.issuer) (not .Values.oidc.clientId)) }}
{{- fail "oidc.issuer and oidc.clientId are required when oidc.enabled is true" }}
{{- end }}
{{- if and .Values.smtp.enabled (or (not .Values.smtp.host) (not .Values.smtp.from)) }}
{{- fail "smtp.host and smtp.from are required when smtp.enabled is true" }}
{{- end }}
{{- if and .Values.metrics.serviceMonitor.useToken (not .Values.metrics.token) (not .Values.secrets.existingSecret) }}
{{- fail "metrics.serviceMonitor.useToken needs metrics.token (or `metrics-token` in secrets.existingSecret)" }}
{{- end }}
{{- end }}
