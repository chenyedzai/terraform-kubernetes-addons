locals {

  external-secrets = merge(
    local.helm_defaults,
    {
      chart                     = local.helm_dependencies[index(local.helm_dependencies.*.name, "external-secrets")].name
      repository                = local.helm_dependencies[index(local.helm_dependencies.*.name, "external-secrets")].repository
      chart_version             = local.helm_dependencies[index(local.helm_dependencies.*.name, "external-secrets")].version
      name                      = "external-secrets"
      namespace                 = "external-secrets"
      service_account_name      = "external-secrets"
      create_ns                 = true
      enabled                   = true
      create_iam_resources_irsa = true
      iam_policy_override       = null
      default_network_policy    = true
      name_prefix               = "${var.cluster-name}-external-secrets"
    }
  ) 

  values_external-secrets = <<-VALUES
  VALUES
}

module "iam_assumable_role_external-secrets" {
  source                        = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version                       = "~> 4.0"
  create_role                   = local.external-secrets["enabled"] && local.external-secrets["create_iam_resources_irsa"]
  role_name                     = local.external-secrets["name_prefix"]
  provider_url                  = replace(var.eks["cluster_oidc_issuer_url"], "https://", "")
  role_policy_arns              = local.external-secrets["enabled"] && local.external-secrets["create_iam_resources_irsa"] ? [aws_iam_policy.external-secrets[0].arn] : []
  number_of_role_policy_arns    = 1
  oidc_fully_qualified_subjects = ["system:serviceaccount:${local.external-secrets["namespace"]}:${local.external-secrets["service_account_name"]}"]
  tags                          = local.tags
}

resource "aws_iam_policy" "external-secrets" {
  count = local.external-secrets["enabled"] && local.external-secrets["create_iam_resources_irsa"] ? 1 : 0
  name     = local.external-secrets["name_prefix"]
  policy   = local.external-secrets["iam_policy_override"] == null ? data.aws_iam_policy_document.external-secrets.json : local.external-secrets["iam_policy_override"]
  tags     = local.tags
}

data "aws_iam_policy_document" "external-secrets" {
  statement {
    effect = "Allow"

    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]

    resources = ["arn:aws:secretsmanager:eu-west-1:${var.arn-partition}:secret:*"]
  }

}

resource "kubernetes_namespace" "external-secrets" {
  count = local.external-secrets["enabled"] && local.external-secrets["create_ns"] ? 1 : 0

  metadata {
    labels = {
      name = local.external-secrets["namespace"]
    }

    name = local.external-secrets["namespace"]
  }
  lifecycle {
    ignore_changes = [
      metadata[0].annotations,
      metadata[0].labels,
    ]
  }  
}

resource "helm_release" "external-secrets" {
  count                 = local.external-secrets["enabled"] ? 1 : 0
  repository            = local.external-secrets["repository"]
  name                  = local.external-secrets["name"]
  chart                 = local.external-secrets["chart"]
  version               = local.external-secrets["chart_version"]
  timeout               = local.external-secrets["timeout"]
  force_update          = local.external-secrets["force_update"]
  recreate_pods         = local.external-secrets["recreate_pods"]
  wait                  = local.external-secrets["wait"]
  atomic                = local.external-secrets["atomic"]
  cleanup_on_fail       = local.external-secrets["cleanup_on_fail"]
  dependency_update     = local.external-secrets["dependency_update"]
  disable_crd_hooks     = local.external-secrets["disable_crd_hooks"]
  disable_webhooks      = local.external-secrets["disable_webhooks"]
  render_subchart_notes = local.external-secrets["render_subchart_notes"]
  replace               = local.external-secrets["replace"]
  reset_values          = local.external-secrets["reset_values"]
  reuse_values          = local.external-secrets["reuse_values"]
  skip_crds             = local.external-secrets["skip_crds"]
  verify                = local.external-secrets["verify"]
  values = [
    local.values_external-secrets,
    local.external-secrets["extra_values"]
  ]
  namespace = local.external-secrets["namespace"]
}
