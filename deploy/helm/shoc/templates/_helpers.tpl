{{- define "shoc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "shoc.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "shoc.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "shoc.labels" -}}
app.kubernetes.io/name: {{ include "shoc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "shoc.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{ .Values.secrets.existingSecret }}
{{- else -}}
{{ include "shoc.fullname" . }}
{{- end -}}
{{- end -}}

{{- define "shoc.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- /* serve and worker never see the owner's DSN: env wins over envFrom (RFC 0024). */ -}}
{{- define "shoc.runtimeEnv" -}}
- name: SHOC_MIGRATE_DSN
  value: ""
{{- end -}}

{{- define "shoc.env" -}}
- name: SHOC_TENANT
  value: {{ .Values.tenant | quote }}
- name: SHOC_BACKEND
  value: {{ .Values.backend | quote }}
- name: SHOC_DRY_RUN
  value: {{ ternary "1" "0" .Values.dryRun | quote }}
- name: SHOC_LLM_PROVIDER
  value: {{ .Values.llm.provider | quote }}
{{- if .Values.llm.model }}
- name: SHOC_LLM_MODEL
  value: {{ .Values.llm.model | quote }}
{{- end }}
{{- if .Values.llm.baseUrl }}
- name: SHOC_LLM_BASE_URL
  value: {{ .Values.llm.baseUrl | quote }}
{{- end }}
{{- end -}}
