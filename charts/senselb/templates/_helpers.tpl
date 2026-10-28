{{/*
Name of the chart, overridable through nameOverride.
*/}}
{{- define "senselb.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Chart label value: name and version, with "+" replaced because a label value
must be a valid DNS-1123 value.
*/}}
{{- define "senselb.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Full name of the release: the prefix for object names. A release name that
already contains the chart name is used on its own, so a release called
"senselb" yields "senselb" rather than "senselb-senselb".
*/}}
{{- define "senselb.fullname" -}}
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
Name shared by the controller's identity: the Deployment, the ServiceAccount
and the four RBAC objects. It is the full name plus "-controller", the name the
plain manifests in config/rbac use.
*/}}
{{- define "senselb.controllerName" -}}
{{- printf "%s-controller" (include "senselb.fullname" . | trunc 52 | trimSuffix "-") }}
{{- end }}

{{/*
Labels applied to every object the chart renders.
*/}}
{{- define "senselb.labels" -}}
helm.sh/chart: {{ include "senselb.chart" . }}
{{ include "senselb.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: senselb
{{- end }}

{{/*
Selector labels. These are immutable on a Deployment, so they carry only the
identifying pair.
*/}}
{{- define "senselb.selectorLabels" -}}
app.kubernetes.io/name: {{ include "senselb.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount the controller runs as. When the chart creates it the name
defaults to the controller name; when it does not, an explicit name is required
so that the bindings never point at a ServiceAccount that does not exist.
*/}}
{{- define "senselb.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "senselb.controllerName" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create is false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Controller image reference. An empty tag falls back to the chart appVersion.
*/}}
{{- define "senselb.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/*
Name of the Secret the controller reads the provider credentials from: the
pre-existing Secret when one is named, otherwise the configured Secret name.
The two ways of naming a Secret exclude each other, so this helper also holds
that check: it is evaluated wherever the name is needed.
*/}}
{{- define "senselb.providerSecretName" -}}
{{- if and .Values.provider.secret.create .Values.provider.secret.existingSecret }}
{{- fail "provider.secret.create and provider.secret.existingSecret are mutually exclusive" }}
{{- end }}
{{- default .Values.provider.secretName .Values.provider.secret.existingSecret }}
{{- end }}
