"""
Terraform and Ansible patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class TerraformAnsibleRules(BaseRule):
    @property
    def name(self) -> str:
        return "terraform_ansible"
    @property
    def description(self) -> str:
        return "Terraform and Ansible patterns"
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
            # Terraform
            (r"resource\s+\"", "Terraform resource", "Good: Terraform resource", Severity.INFO),
            (r"data\s+\"", "Terraform data source", "Good: data source", Severity.INFO),
            (r"variable\s+\"", "Terraform variable", "Good: variable", Severity.INFO),
            (r"output\s+\"", "Terraform output", "Good: output", Severity.INFO),
            (r"module\s+\"", "Terraform module", "Good: module", Severity.INFO),
            (r"provider\s+\"", "Terraform provider", "Good: provider", Severity.INFO),
            (r"backend\s+\"", "Terraform backend", "Good: backend", Severity.INFO),
            (r"locals\s*\{", "Terraform locals", "Good: locals", Severity.INFO),
            (r"provisioner\s+\"", "Terraform provisioner", "Good: provisioner", Severity.INFO),
            (r"lifecycle\s*\{", "Terraform lifecycle", "Good: lifecycle", Severity.INFO),
            (r"depends_on\s*=|depends_on\s*\[", "Terraform depends_on", "Good: depends_on", Severity.INFO),
            (r"count\s*=|count\s*\{", "Terraform count", "Good: count", Severity.INFO),
            (r"for_each\s*=|for_each\s*\{", "Terraform for_each", "Good: for_each", Severity.INFO),
            (r"dynamic\s+\"", "Terraform dynamic", "Good: dynamic", Severity.INFO),
            (r"terraform\s*\{", "Terraform block", "Good: terraform block", Severity.INFO),
            (r"required_providers|required_version", "Terraform requirements", "Good: requirements", Severity.INFO),
            # AWS provider
            (r"aws_|azurerm_|google_|azuread_|helm_|kubernetes_|random_|local_|null_|template_|tls_|acme_|cloudflare_|digitalocean_|linode_|vultr_|hetzner_|github_|pagerduty_|datadog_|sumologic_|elastic_|newrelic_|grafana_|auth0_|okta_", "Provider resource", "Good: provider resource", Severity.INFO),
            (r"aws_instance|aws_vpc|aws_subnet|aws_security_group|aws_iam|aws_s3|aws_lambda|aws_api_gateway|aws_dynamodb|aws_rds|aws_elasticache|aws_cloudfront|aws_route53|aws_ebs|aws_eip|aws_nat|aws_internet|aws_alb|aws_elb|aws_sqs|aws_sns|aws_kms|aws_secretsmanager|aws_ssm|aws_ecs|aws_eks|aws_fargate|aws_cloudwatch|aws_kinesis|aws_glue|aws_athena|aws_redshift|aws_emr", "AWS resource", "Good: AWS resource", Severity.INFO),
            (r"azurerm_virtual_machine|azurerm_resource_group|azurerm_virtual_network|azurerm_subnet|azurerm_network_security_group|azurerm_storage_account|azurerm_key_vault|azurerm_app_service|azurerm_function_app|azurerm_sql|azurerm_cosmosdb|azurerm_redis|azurerm_dns|azurerm_cdn|azurerm_lb|azurerm_public_ip", "Azure resource", "Good: Azure resource", Severity.INFO),
            (r"google_compute_instance|google_compute_network|google_compute_subnetwork|google_compute_firewall|google_storage_bucket|google_cloudfunctions_function|google_bigquery_dataset|google_cloud_run_service|google_cloud_build_trigger|google_redis_instance|google_sql_database_instance|google_compute_address|google_compute_global_address|google_dns_managed_zone", "GCP resource", "Good: GCP resource", Severity.INFO),
            (r"azurerm_|azuread_", "Azure provider", "Good: Azure provider", Severity.INFO),
            (r"google_|gcp_", "GCP provider", "Good: GCP provider", Severity.INFO),
            (r"aws_|amazon_", "AWS provider", "Good: AWS provider", Severity.INFO),
            (r"kubernetes_|helm_", "Kubernetes provider", "Good: Kubernetes provider", Severity.INFO),
            (r"cloudflare_", "Cloudflare provider", "Good: Cloudflare provider", Severity.INFO),
            # Terraform commands
            (r"terraform\s+init|terraform\s+plan|terraform\s+apply|terraform\s+destroy|terraform\s+import|terraform\s+state|terraform\s+fmt|terraform\s+validate|terraform\s+output|terraform\s+console|terraform\s+taint|terraform\s+untaint|terraform\s+graph|terraform\s+workspace|terraform\s+providers|terraform\s+version|terraform\s+refresh|terraform\s+show|terraform\s+test|terraform\s+login|terraform\s+logout|terraform\s+chdir|terraform\s+env", "Terraform command", "Good: Terraform command", Severity.INFO),
            # Ansible
            (r"tasks:|handlers:|vars:|defaults:|files:|templates:|meta:|roles:|playbooks:", "Ansible structure", "Good: Ansible structure", Severity.INFO),
            (r"name:|hosts:|become:|gather_facts:|vars:|tasks:|handlers:|roles:|tags:|serial:|strategy:|any_errors_fatal:|max_fail_percentage:", "Ansible play", "Good: Ansible play", Severity.INFO),
            (r"copy:|file:|template:|lineinfile:|blockinfile:|service:|package:|yum:|apt:|pip:|npm:|git:|command:|shell:|user:|group:|cron:|sysctl:|wait_for:|uri:|debug:|assert:|set_fact:|register:|when:|with_items:|loop:|until:|retries:|delay:|ignore_errors:", "Ansible module", "Good: Ansible module", Severity.INFO),
            # Ansible patterns
            (r"become_method:\s+\w+", "Become method", "Good: become method", Severity.INFO),
            (r"become_user:\s+\w+", "Become user", "Good: become user", Severity.INFO),
            (r"ansible_host:|ansible_user:|ansible_port:|ansible_ssh_private_key_file:|ansible_become:|ansible_become_method:|ansible_become_user:", "Inventory variable", "Good: inventory variable", Severity.INFO),
            (r"group_vars/|host_vars/|inventory\.ini|inventory\.yml|ansible\.cfg", "Ansible file", "Good: Ansible file", Severity.INFO),
            # Ansible roles
            (r"meta/main\.yml|tasks/main\.yml|handlers/main\.yml|vars/main\.yml|defaults/main\.yml|files/|templates/|tests/", "Role structure", "Good: role structure", Severity.INFO),
            (r"dependencies:\s*\[|dependencies:\s*$", "Role dependencies", "Good: role dependencies", Severity.INFO),
            # Ansible vault
            (r"ansible-vault\s+encrypt|ansible-vault\s+decrypt|ansible-vault\s+edit|ansible-vault\s+view|ansible-vault\s+create|ansible-vault\s+migrate|ansible-vault\s+rekey|ansible-vault\s+encrypt_string", "Vault command", "Good: Ansible vault", Severity.INFO),
            (r"!vault\s*\||\$\!vault\|", "Vault variable", "Good: vault variable", Severity.INFO),
            # Ansible commands
            (r"ansible\s+\w+\s+-m\s+\w+|ansible-playbook\s+\w+|ansible-galaxy\s+\w+|ansible-vault\s+\w+|ansible-inventory\s+\w+|ansible-config\s+\w+|ansible-doc\s+\w+|ansible-lint\s+\w+", "Ansible command", "Good: Ansible command", Severity.INFO),
            # Ansible tools
            (r"ansible|Ansible|ansible-lint|ansible-compat|molecule|testinfra|yamllint|ansible-navigator|ansible-builder|ansible-runner|awx|tower|Semaphore|AWX", "Ansible tool", "Good: Ansible tools", Severity.INFO),
            # IaC best practices
            (r"remote_state|backend|state_file|state_lock|state_encryption", "State management", "Good: state management", Severity.INFO),
            (r"drift|plan\.out|apply\.json|import\.tf", "IaC operations", "Good: IaC operations", Severity.INFO),
            (r"terraform-docs|tflint|tfsec|checkov|infracost|terragrunt|terratest", "Terraform tools", "Good: Terraform tools", Severity.INFO),
            (r"ansible-lint|ansible-navigator|molecule|yamllint|testinfra|galaxy|lint", "Ansible tools", "Good: Ansible tools", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('# '):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
