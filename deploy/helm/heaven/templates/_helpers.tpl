{{/*
Standard Helm helpers — names, labels, selectorLabels, serviceAccountName.
*/}}

{{- define "heaven.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "heaven.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "heaven.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "heaven.labels" -}}
helm.sh/chart: {{ include "heaven.chart" . }}
{{ include "heaven.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "heaven.selectorLabels" -}}
app.kubernetes.io/name: {{ include "heaven.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "heaven.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "heaven.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end -}}

{{- define "heaven.secretName" -}}
{{- printf "%s-secrets" (include "heaven.fullname" .) -}}
{{- end -}}

{{- define "heaven.configMapName" -}}
{{- printf "%s-config" (include "heaven.fullname" .) -}}
{{- end -}}
