"""
Docker and Kubernetes patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class DockerKubernetesRules(BaseRule):
    @property
    def name(self) -> str:
        return "docker_kubernetes"
    @property
    def description(self) -> str:
        return "Docker and Kubernetes patterns"
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE
    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        patterns = [
            # Docker
            (r"FROM\s+", "Base image", "Good: Docker FROM", Severity.INFO),
            (r"RUN\s+", "Run command", "Good: Docker RUN", Severity.INFO),
            (r"COPY\s+", "Copy files", "Good: Docker COPY", Severity.INFO),
            (r"ADD\s+", "Add files", "Good: Docker ADD", Severity.INFO),
            (r"CMD\s+", "Default command", "Good: Docker CMD", Severity.INFO),
            (r"ENTRYPOINT\s+", "Entrypoint", "Good: Docker ENTRYPOINT", Severity.INFO),
            (r"ENV\s+", "Environment variable", "Good: Docker ENV", Severity.INFO),
            (r"ARG\s+", "Build argument", "Good: Docker ARG", Severity.INFO),
            (r"EXPOSE\s+", "Expose port", "Good: Docker EXPOSE", Severity.INFO),
            (r"VOLUME\s+", "Volume", "Good: Docker VOLUME", Severity.INFO),
            (r"WORKDIR\s+", "Working directory", "Good: Docker WORKDIR", Severity.INFO),
            (r"USER\s+", "User", "Good: Docker USER", Severity.INFO),
            (r"LABEL\s+", "Label", "Good: Docker LABEL", Severity.INFO),
            (r"HEALTHCHECK\s+", "Health check", "Good: Docker HEALTHCHECK", Severity.INFO),
            (r"SHELL\s+", "Shell", "Good: Docker SHELL", Severity.INFO),
            (r"STOPSIGNAL\s+", "Stop signal", "Good: Docker STOPSIGNAL", Severity.INFO),
            (r"ONBUILD\s+", "On build", "Good: Docker ONBUILD", Severity.INFO),
            (r"docker\.ignore|\.dockerignore", "Docker ignore", "Good: .dockerignore", Severity.INFO),
            (r"docker-compose\.ya?ml|compose\.ya?ml", "Compose file", "Good: docker-compose", Severity.INFO),
            (r"docker\s+build|docker\s+run|docker\s+exec|docker\s+ps|docker\s+images|docker\s+pull|docker\s+push|docker\s+tag|docker\s+inspect|docker\s+logs|docker\s+stop|docker\s+start|docker\s+restart|docker\s+rm|docker\s+rmi|docker\s+system|docker\s+builder|docker\s+manifest|docker\s+swarm|docker\s+service|docker\s+node|docker\s+config|docker\s+secret", "Docker command", "Good: Docker command", Severity.INFO),
            # Kubernetes
            (r"apiVersion:\s+", "Kubernetes API version", "Good: Kubernetes apiVersion", Severity.INFO),
            (r"kind:\s+", "Kubernetes kind", "Good: Kubernetes kind", Severity.INFO),
            (r"metadata:\s+", "Kubernetes metadata", "Good: Kubernetes metadata", Severity.INFO),
            (r"spec:\s+", "Kubernetes spec", "Good: Kubernetes spec", Severity.INFO),
            (r"Deployment|Service|Pod|Ingress|ConfigMap|Secret|StatefulSet|DaemonSet|CronJob|Job|Namespace|RBAC|Role|ClusterRole|Binding|ServiceAccount|PersistentVolume|PersistentVolumeClaim|StorageClass|NetworkPolicy|PodSecurityPolicy", "Kubernetes resource", "Good: Kubernetes resource", Severity.INFO),
            (r"replicas:\s+", "Replicas", "Good: replicas", Severity.INFO),
            (r"selector:\s+", "Selector", "Good: selector", Severity.INFO),
            (r"template:\s+", "Template", "Good: template", Severity.INFO),
            (r"containers:\s+", "Containers", "Good: containers", Severity.INFO),
            (r"ports:\s+", "Ports", "Good: ports", Severity.INFO),
            (r"env:\s+", "Environment", "Good: environment", Severity.INFO),
            (r"resources:\s+", "Resources", "Good: resources", Severity.INFO),
            (r"limits:\s+", "Limits", "Good: limits", Severity.INFO),
            (r"requests:\s+", "Requests", "Good: requests", Severity.INFO),
            (r"volumeMounts:\s+", "Volume mounts", "Good: volume mounts", Severity.INFO),
            (r"volumes:\s+", "Volumes", "Good: volumes", Severity.INFO),
            (r"livenessProbe:\s+", "Liveness probe", "Good: liveness probe", Severity.INFO),
            (r"readinessProbe:\s+", "Readiness probe", "Good: readiness probe", Severity.INFO),
            (r"startupProbe:\s+", "Startup probe", "Good: startup probe", Severity.INFO),
            (r"serviceAccountName:\s+", "Service account", "Good: service account", Severity.INFO),
            (r"nodeSelector:\s+", "Node selector", "Good: node selector", Severity.INFO),
            (r"tolerations:\s+", "Tolerations", "Good: tolerations", Severity.INFO),
            (r"affinity:\s+", "Affinity", "Good: affinity", Severity.INFO),
            (r"initContainers:\s+", "Init containers", "Good: init containers", Severity.INFO),
            (r"containers:\s+", "Containers", "Good: containers", Severity.INFO),
            (r"terminationGracePeriodSeconds:\s+", "Grace period", "Good: grace period", Severity.INFO),
            (r"restartPolicy:\s+", "Restart policy", "Good: restart policy", Severity.INFO),
            (r"imagePullPolicy:\s+", "Image pull policy", "Good: image pull policy", Severity.INFO),
            (r"imagePullSecrets:\s+", "Image pull secrets", "Good: image pull secrets", Severity.INFO),
            # Helm
            (r"apiVersion:\s+v2|kind:\s+Chart", "Helm chart", "Good: Helm chart", Severity.INFO),
            (r"name:\s+\w+|version:\s+\d+\.\d+\.\d+|appVersion:\s+", "Chart metadata", "Good: chart metadata", Severity.INFO),
            (r"dependencies:\s+|Chart\.yaml|values\.yaml|templates/|helpers/", "Helm structure", "Good: Helm structure", Severity.INFO),
            (r"\.Values\.\w+", "Helm values", "Good: Helm values", Severity.INFO),
            (r"\.Release\.\w+|\.Chart\.\w+|\.Capabilities\.\w+|\.Template\.\w+", "Helm objects", "Good: Helm objects", Severity.INFO),
            (r"helm\s+install|helm\s+upgrade|helm\s+uninstall|helm\s+list|helm\s+search|helm\s+repo|helm\s+dependency|helm\s+package|helm\s+lint|helm\s+template|helm\s+show|helm\s+pull|helm\s+push|helm\s+chart", "Helm command", "Good: Helm command", Severity.INFO),
            # Kubernetes tools
            (r"kubectl\s+apply|kubectl\s+get|kubectl\s+describe|kubectl\s+logs|kubectl\s+exec|kubectl\s+port-forward|kubectl\s+delete|kubectl\s+create|kubectl\s+edit|kubectl\s+patch|kubectl\s+scale|kubectl\s+cordon|kubectl\s+uncordon|kubectl\s+drain|kubectl\s+taint|kubectl\s+label|kubectl\s+annotate|kubectl\s+config|kubectl\s+cluster-info|kubectl\s+top|kubectl\s+cp", "kubectl command", "Good: kubectl", Severity.INFO),
            (r"kubectx|kubens|k9s|kubetail|kube-ps1|kubecolor|kubie", "K8s tools", "Good: K8s tools", Severity.INFO),
            (r"minikube|kind|k3s|k3d|rke|k0s|microk8s|EKS|GKE|AKS|OpenShift", "K8s distribution", "Good: K8s distribution", Severity.INFO),
            # Service mesh
            (r"Istio|Envoy|Linkerd|Cilium|Consul|Ambassador|Emissary|Kong|APISIX|Traefik", "Service mesh", "Good: service mesh", Severity.INFO),
            (r"VirtualService|DestinationRule|Gateway|ServiceEntry|Sidecar|EnvoyFilter|RequestAuthentication|AuthorizationPolicy|PeerAuthentication", "Istio resource", "Good: Istio resource", Severity.INFO),
            # GitOps
            (r"ArgoCD|Flux|Weave|Tekton|Spinnaker|Harness", "GitOps tool", "Good: GitOps tools", Severity.INFO),
            (r"Application|ApplicationSet|AppProject", "ArgoCD resource", "Good: ArgoCD resource", Severity.INFO),
            (r"Kustomization|HelmRelease|HelmRepository|GitRepository|OCIRepository|Bucket|ImageRepository|ImagePolicy|ImageUpdateAutomation", "Flux resource", "Good: Flux resource", Severity.INFO),
            # Container security
            (r"readOnlyRootFilesystem:\s+true", "Read-only filesystem", "Good: read-only filesystem", Severity.INFO),
            (r"allowPrivilegeEscalation:\s+false", "No privilege escalation", "Good: no privilege escalation", Severity.INFO),
            (r"runAsNonRoot:\s+true", "Run as non-root", "Good: run as non-root", Severity.INFO),
            (r"runAsUser:\s+", "Run as user", "Good: run as user", Severity.INFO),
            (r"securityContext:\s+", "Security context", "Good: security context", Severity.INFO),
            (r"capabilities:\s+", "Capabilities", "Good: capabilities", Severity.INFO),
            (r"drop:\s+\[ALL\]", "Drop all capabilities", "Good: drop all capabilities", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
