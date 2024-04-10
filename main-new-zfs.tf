################################################################################
# AWS FSx for OpenZFS CSI DRIVER
################################################################################

locals {
  aws_fsx_zfs_csi_driver_controller_service_account = try(var.aws_fsx_zfs_csi_driver.controller_service_account_name, "fsx-openzfs-csi-controller-sa")
  aws_fsx_zfs_csi_driver_node_service_account       = try(var.aws_fsx_zfs_csi_driver.node_service_account_name, "fsx-openzfs-csi-node-sa")
  aws_fsx_zfs_csi_driver_namespace                  = try(var.aws_fsx_zfs_csi_driver.namespace, "kube-system")
  
  # # https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonfsx.html#amazonfsx-resources-for-iam-policies
  # fsx_zfs_arns = lookup(var.aws_fsx_zfs_csi_driver, "fsx_zfs_arns",
  #   ["arn:${local.partition}:fsx:${local.region}:${local.account_id}:file-system/*"],
  # )
  # fsx_zfs_volume_arns = lookup(var.aws_fsx_zfs_csi_driver, "fsx_zfs_volume_arns",
  #   ["arn:${local.partition}:fsx:${local.region}:${local.account_id}:volume/*"]
  # )
}

# data "aws_iam_policy_document" "aws_fsx_zfs_csi_driver" {
#   count = var.enable_aws_fsx_zfs_csi_driver ? 1 : 0
#
#   source_policy_documents   = lookup(var.aws_fsx_zfs_csi_driver, "source_policy_documents", [])
#   override_policy_documents = lookup(var.aws_fsx_zfs_csi_driver, "override_policy_documents", [])
#
#   statement {
#     sid       = "gh01"
#     actions   = [
#       "iam:CreateServiceLinkedRole",
#       "iam:AttachRolePolicy",
#       "iam:PutRolePolicy",
#     ]
#     resources = ["*"]
#   }
#
#   statement {
#     sid = "AllowDescribeFileSystems"
#     actions = [
#       "elasticfilesystem:DescribeAccessPoints",
#       "elasticfilesystem:DescribeFileSystems",
#       "elasticfilesystem:DescribeMountTargets"
#     ]
#     resources = flatten([
#       local.fsx_zfs_arns,
#       local.fsx_zfs_volume_arns,
#     ])
#   }
#
#   statement {
#     actions = [
#       "elasticfilesystem:CreateAccessPoint",
#       "elasticfilesystem:TagResource",
#     ]
#     resources = local.fsx_zfs_arns
#
#     condition {
#       test     = "StringLike"
#       variable = "aws:RequestTag/efs.csi.aws.com/cluster"
#       values   = ["true"]
#     }
#   }
#
#   statement {
#     sid       = "AllowDeleteAccessPoint"
#     actions   = ["elasticfilesystem:DeleteAccessPoint"]
#     resources = local.fsx_zfs_volume_arns
#
#     condition {
#       test     = "StringLike"
#       variable = "aws:ResourceTag/efs.csi.aws.com/cluster"
#       values   = ["true"]
#     }
#   }
#
#   statement {
#     sid = "ClientReadWrite"
#     actions = [
#       "elasticfilesystem:ClientRootAccess",
#       "elasticfilesystem:ClientWrite",
#       "elasticfilesystem:ClientMount",
#     ]
#     resources = local.fsx_zfs_arns
#
#     condition {
#       test     = "Bool"
#       variable = "elasticfilesystem:AccessedViaMountTarget"
#       values   = ["true"]
#     }
#   }
# }

module "aws_fsx_zfs_csi_driver" {
  source  = "aws-ia/eks-blueprints-addon/aws"
  version = "1.1.1"

  create = var.enable_aws_fsx_zfs_csi_driver

  # Disable helm release
  create_release = var.create_kubernetes_resources

  # https://github.com/kubernetes-sigs/aws-fsx-openzfs-csi-driver/tree/main/charts/aws-fsx-openzfs-csi-driver
  name             = try(var.aws_fsx_zfs_csi_driver.name, "aws-fsx-openzfs-csi-driver")
  description      = try(var.aws_fsx_zfs_csi_driver.description, "A Helm chart to deploy aws-fsx-openzfs-csi-driver")
  namespace        = local.aws_fsx_zfs_csi_driver_namespace
  create_namespace = try(var.aws_fsx_zfs_csi_driver.create_namespace, false)
  chart            = try(var.aws_fsx_zfs_csi_driver.chart, "aws-fsx-openzfs-csi-driver")
  chart_version    = try(var.aws_fsx_zfs_csi_driver.chart_version, "1.1.0")
  repository       = try(var.aws_fsx_zfs_csi_driver.repository, "https://kubernetes-sigs.github.io/aws-fsx-openzfs-csi-driver/")
  values           = try(var.aws_fsx_zfs_csi_driver.values, [])

  timeout                    = try(var.aws_fsx_zfs_csi_driver.timeout, null)
  repository_key_file        = try(var.aws_fsx_zfs_csi_driver.repository_key_file, null)
  repository_cert_file       = try(var.aws_fsx_zfs_csi_driver.repository_cert_file, null)
  repository_ca_file         = try(var.aws_fsx_zfs_csi_driver.repository_ca_file, null)
  repository_username        = try(var.aws_fsx_zfs_csi_driver.repository_username, null)
  repository_password        = try(var.aws_fsx_zfs_csi_driver.repository_password, null)
  devel                      = try(var.aws_fsx_zfs_csi_driver.devel, null)
  verify                     = try(var.aws_fsx_zfs_csi_driver.verify, null)
  keyring                    = try(var.aws_fsx_zfs_csi_driver.keyring, null)
  disable_webhooks           = try(var.aws_fsx_zfs_csi_driver.disable_webhooks, null)
  reuse_values               = try(var.aws_fsx_zfs_csi_driver.reuse_values, null)
  reset_values               = try(var.aws_fsx_zfs_csi_driver.reset_values, null)
  force_update               = try(var.aws_fsx_zfs_csi_driver.force_update, null)
  recreate_pods              = try(var.aws_fsx_zfs_csi_driver.recreate_pods, null)
  cleanup_on_fail            = try(var.aws_fsx_zfs_csi_driver.cleanup_on_fail, null)
  max_history                = try(var.aws_fsx_zfs_csi_driver.max_history, null)
  atomic                     = try(var.aws_fsx_zfs_csi_driver.atomic, null)
  skip_crds                  = try(var.aws_fsx_zfs_csi_driver.skip_crds, null)
  render_subchart_notes      = try(var.aws_fsx_zfs_csi_driver.render_subchart_notes, null)
  disable_openapi_validation = try(var.aws_fsx_zfs_csi_driver.disable_openapi_validation, null)
  wait                       = try(var.aws_fsx_zfs_csi_driver.wait, false)
  wait_for_jobs              = try(var.aws_fsx_zfs_csi_driver.wait_for_jobs, null)
  dependency_update          = try(var.aws_fsx_zfs_csi_driver.dependency_update, null)
  replace                    = try(var.aws_fsx_zfs_csi_driver.replace, null)
  lint                       = try(var.aws_fsx_zfs_csi_driver.lint, null)

  postrender = try(var.aws_fsx_zfs_csi_driver.postrender, [])
  set = concat([
    {
      name  = "controller.serviceAccount.name"
      value = local.aws_fsx_zfs_csi_driver_controller_service_account
    },
    {
      name  = "node.serviceAccount.name"
      value = local.aws_fsx_zfs_csi_driver_node_service_account
    }],
    try(var.aws_fsx_zfs_csi_driver.set, [])
  )
  set_sensitive = try(var.aws_fsx_zfs_csi_driver.set_sensitive, [])

  # IAM role for service account (IRSA)
  set_irsa_names = [
    "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn",
    "node.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
  ]
  create_role                   = try(var.aws_fsx_zfs_csi_driver.create_role, true)
  role_name                     = try(var.aws_fsx_zfs_csi_driver.role_name, "aws-fsx-openzfs-csi-driver")
  role_name_use_prefix          = try(var.aws_fsx_zfs_csi_driver.role_name_use_prefix, true)
  role_path                     = try(var.aws_fsx_zfs_csi_driver.role_path, "/")
  role_permissions_boundary_arn = lookup(var.aws_fsx_zfs_csi_driver, "role_permissions_boundary_arn", null)
  role_description              = try(var.aws_fsx_zfs_csi_driver.role_description, "IRSA for aws-fsx-openzfs-csi-driver project")
  role_policies                 = lookup(var.aws_fsx_zfs_csi_driver, "role_policies", {})

  # source_policy_documents = data.aws_iam_policy_document.aws_fsx_zfs_csi_driver[*].json
  source_policy_documents = lookup(var.aws_fsx_zfs_csi_driver, "source_policy_documents", [])
  policy_statements       = lookup(var.aws_fsx_zfs_csi_driver, "policy_statements", [])
  policy_name             = try(var.aws_fsx_zfs_csi_driver.policy_name, null)
  policy_name_use_prefix  = try(var.aws_fsx_zfs_csi_driver.policy_name_use_prefix, true)
  policy_path             = try(var.aws_fsx_zfs_csi_driver.policy_path, null)
  policy_description      = try(var.aws_fsx_zfs_csi_driver.policy_description, "IAM Policy for AWS FSx for OpenZFS CSI Driver")

  oidc_providers = {
    controller = {
      provider_arn = local.oidc_provider_arn
      # namespace is inherited from chart
      service_account = local.aws_fsx_zfs_csi_driver_controller_service_account
    }
    node = {
      provider_arn = local.oidc_provider_arn
      # namespace is inherited from chart
      service_account = local.aws_fsx_zfs_csi_driver_node_service_account
    }
  }

  tags = var.tags
}