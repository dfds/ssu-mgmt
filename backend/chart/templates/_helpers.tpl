{{/*
Expand the name of the chart.
*/}}
{{- define "ssu-mgmt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "ssu-mgmt.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" $name .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "ssu-mgmt-gendis.fullname" -}}
{{- if .Values.gendis.fullnameOverride }}
{{- .Values.gendis.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s-gendis" $name .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "ssu-mgmt.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ssu-mgmt.labels" -}}
{{ include "ssu-mgmt.selectorLabels" . }}
{{- if eq .Values.managedByHelm true }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "ssu-mgmt.chart" . }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ssu-mgmt-gendis.labels" -}}
{{ include "ssu-mgmt-gendis.selectorLabels" . }}
{{- if eq .Values.managedByHelm true }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ include "ssu-mgmt.chart" . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ssu-mgmt.selectorLabels" -}}
app: {{ include "ssu-mgmt.fullname" . }}
app.kubernetes.io/name: {{ include "ssu-mgmt.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels gendis
*/}}
{{- define "ssu-mgmt-gendis.selectorLabels" -}}
app: {{ include "ssu-mgmt.fullname" . }}-gendis
app.kubernetes.io/name: {{ include "ssu-mgmt.name" . }}-gendis
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "ssu-mgmt.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ssu-mgmt.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "ssu-mgmt-gendis.serviceAccountName" -}}
{{- if .Values.gendis.serviceAccount.create }}
{{- default (include "ssu-mgmt-gendis.fullname" .) .Values.gendis.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.gendis.serviceAccount.name }}
{{- end }}
{{- end }}