{{/*
Names and labels.
*/}}
{{- define "starling.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "starling.fullname" -}}
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

{{- define "starling.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "starling.labels" -}}
helm.sh/chart: {{ include "starling.chart" . }}
{{ include "starling.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "starling.selectorLabels" -}}
app.kubernetes.io/name: {{ include "starling.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "starling.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{- define "starling.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "starling.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
The Kubernetes Service name a Starling service is dialled at.

One name for both directions: it is what goes in the config file's `endpoint`,
and it is what the Service object is called.
*/}}
{{- define "starling.svcName" -}}
{{- printf "%s-%s" (include "starling.fullname" .root) .name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
The environment variable that overrides one config key.

docs/CONFIGURATION.md: uppercase, dots and dashes to underscores, STARLING_
prefix. `link-preview` becomes LINK_PREVIEW, which is why this is computed and
never split back apart.
*/}}
{{- define "starling.envKey" -}}
{{- printf "STARLING_SERVICES_%s_%s" (.name | replace "-" "_" | upper) .key }}
{{- end }}

{{/*
The gRPC port a service serves on.

50051 for everything except a colocated voice: two containers in one pod share
a network namespace, so voice and the gateway cannot both bind 50051.
*/}}
{{- define "starling.grpcPort" -}}
{{- if and (eq .name "voice") .root.Values.voice.colocateWithGateway -}}
{{- .root.Values.voice.colocatedGrpcPort -}}
{{- else -}}
50051
{{- end -}}
{{- end }}

{{/*
What one workload binds, as an environment variable.

The config file's `endpoint` says `http://<service>:50051` so that every *other*
service knows where to dial. That name resolves to a ClusterIP, which is a
virtual address belonging to no interface, so a pod that tried to bind it would
fail to start.

`bind` is the half of the pair that says where to listen, and it is set per
container rather than in the shared ConfigMap because each one answers for
itself. The address others dial is left alone, so nothing has to agree with a
value only one pod can see.
*/}}
{{- define "starling.bindEnv" -}}
- name: {{ include "starling.envKey" (dict "name" .name "key" "BIND") }}
  value: "http://0.0.0.0:{{ include "starling.grpcPort" (dict "name" .name "root" .root) }}"
{{- end }}

{{/*
Everything every container gets.
*/}}
{{- define "starling.commonEnv" -}}
- name: RUST_LOG
  value: {{ .Values.logLevel | quote }}
{{- if and .Values.operatorApi.enabled (eq .Values.operatorApi.auth.mode "token") }}
- name: STARLING_ADMIN_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.operatorApi.auth.token.existingSecret | default (printf "%s-admin" (include "starling.fullname" .)) }}
      key: {{ .Values.operatorApi.auth.token.existingSecretKey }}
      optional: true
{{- end }}
{{- end }}

{{/*
The config file and, when one is configured, the gateway's certificate.
*/}}
{{- define "starling.volumeMounts" -}}
- name: config
  mountPath: /etc/starling
  readOnly: true
- name: data
  mountPath: {{ .Values.runtime.dataDir }}
{{- if .Values.gateway.tls.existingSecret }}
- name: tls
  mountPath: {{ .Values.gateway.tls.mountPath }}
  readOnly: true
{{- end }}
{{- end }}

{{- define "starling.volumes" -}}
- name: config
  configMap:
    name: {{ include "starling.fullname" . }}
{{- if .Values.gateway.tls.existingSecret }}
- name: tls
  secret:
    secretName: {{ .Values.gateway.tls.existingSecret }}
{{- end }}
{{- end }}

{{/*
A TCP readiness/liveness pair against a port.

Readiness means the listener is up, not that the caches behind it are warm. The
runtime's real readiness is an in-process gate served over
`starling.health.v1.Health`, and a native Kubernetes `grpc:` probe speaks
`grpc.health.v1.Health`, so it cannot read it. See the chart README.
*/}}
{{- define "starling.tcpProbes" -}}
{{- $p := .probes -}}
{{- if $p.enabled }}
readinessProbe:
  tcpSocket:
    port: {{ .port }}
  initialDelaySeconds: {{ $p.readiness.initialDelaySeconds }}
  periodSeconds: {{ $p.readiness.periodSeconds }}
  timeoutSeconds: {{ $p.readiness.timeoutSeconds }}
  failureThreshold: {{ $p.readiness.failureThreshold }}
livenessProbe:
  tcpSocket:
    port: {{ .port }}
  initialDelaySeconds: {{ $p.liveness.initialDelaySeconds }}
  periodSeconds: {{ $p.liveness.periodSeconds }}
  timeoutSeconds: {{ $p.liveness.timeoutSeconds }}
  failureThreshold: {{ $p.liveness.failureThreshold }}
{{- end }}
{{- end }}

{{/*
The per-service settings a values entry may override, falling back to defaults.
*/}}
{{- define "starling.podSpecExtras" -}}
{{- $svc := .svc -}}
{{- $d := .root.Values.defaults -}}
{{- with (default $d.nodeSelector $svc.nodeSelector) }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with (default $d.tolerations $svc.tolerations) }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with (default $d.affinity $svc.affinity) }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Whether a service keeps anything across a restart.

Every service writes a SQLite file named after itself under `data_dir` unless
it is pointed at a real database, so this defaults to on.
*/}}
{{- define "starling.wantsVolume" -}}
{{- $svc := .svc -}}
{{- $global := .root.Values.persistence.enabled -}}
{{- if not $global -}}
false
{{- else if and $svc.persistence (hasKey $svc.persistence "enabled") -}}
{{- ternary "true" "false" $svc.persistence.enabled -}}
{{- else if and $svc.storage $svc.storage.url -}}
false
{{- else -}}
true
{{- end -}}
{{- end }}

{{/*
The services that get their own workload in "services" mode.

Excludes the gateway, which has its own template because of the client-facing
ports and the voice sidecar, and excludes voice itself while it is colocated.
*/}}
{{- define "starling.standaloneServices" -}}
{{- $out := list -}}
{{- range $name, $svc := .Values.services -}}
{{- if $svc.enabled -}}
{{- if and (ne $name "gateway") (not (and (eq $name "voice") $.Values.voice.colocateWithGateway)) -}}
{{- $out = append $out $name -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- toJson $out -}}
{{- end }}
