{{/*
Expand the name of the chart.
*/}}
{{- define "dne.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "dne.fullname" -}}
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

{{/*
Chart name and version label.
*/}}
{{- define "dne.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every object.
*/}}
{{- define "dne.labels" -}}
helm.sh/chart: {{ include "dne.chart" . }}
{{ include "dne.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: dne
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "dne.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dne.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name to use.
*/}}
{{- define "dne.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "dne.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
The container image to use, falling back to chart appVersion.
*/}}
{{- define "dne.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{ .Values.image.repository }}:{{ $tag }}
{{- end }}

{{/*
The namespace where the Grafana dashboard ConfigMap lives.
*/}}
{{- define "dne.dashboardNamespace" -}}
{{- default .Release.Namespace .Values.grafanaDashboard.namespace }}
{{- end }}

{{/*
Render dne CLI args from values.
*/}}
{{- define "dne.args" -}}
{{- if .Values.namespaces }}
- --namespaces={{ join "," .Values.namespaces }}
{{- end }}
{{- if .Values.labelSelector }}
- --label-selector={{ .Values.labelSelector }}
{{- end }}
- --metrics-bind-address=:{{ .Values.metricsPort }}
- --health-probe-bind-address=:{{ .Values.healthPort }}
- --log-level={{ .Values.logLevel }}
{{- if .Values.leaderElection.enabled }}
- --leader-elect=true
- --leader-election-id={{ .Values.leaderElection.id }}
{{- end }}
{{- range .Values.extraArgs }}
- {{ . | quote }}
{{- end }}
{{- end }}
