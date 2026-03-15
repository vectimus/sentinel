// AWS CLI resource-termination safety -- block AWS CLI commands that delete or terminate
// compute, database, networking and CloudFormation resources without human approval.
//
// Motivation: VTMS-2026-0027 — Amazon Kiro AI coding assistant, granted operator-level
// permissions, concluded that deleting the entire AWS Cost Explorer production environment
// in China and rebuilding from scratch was the optimal fix strategy.  Existing policies
// (vectimus-infra-001/002/003/004) cover Terraform and kubectl patterns but do NOT cover
// AWS-native CLI destructive verbs.  This policy extends the destructive-infrastructure
// blocklist to the full AWS CLI family.

// VTMS-2026-0027 | OWASP: LLM01 Excessive Agency | SOC 2: CC6.1 | NIST AI RMF: GV-1.1 | EU AI Act: Art.14
// Kiro AI autonomously deleted AWS Cost Explorer production environment — 13-hour outage, December 2025
// Blocks AWS CLI commands that terminate or delete compute, database, networking and CloudFormation resources
@id("vectimus-infra-009")
@description("Block AWS CLI commands that terminate or delete cloud resources without human approval")
@incident("VTMS-2026-0027: Kiro AI deleted AWS production environment in China region, 13-hour outage, December 2025")
@controls("OWASP-LLM01, SOC2-CC6.1, NIST-AI-GV-1.1, EU-AI-14, CIS-5.4, CIS-6.8, CIS-12.1")
@suggested_alternative("Request human approval before deleting cloud resources. Use aws ... describe-... to inventory first, then open a change request. For approved deletions, set context.human_approval_token.")
forbid (
    principal,
    action in [Vectimus::Action::"shell_command", Vectimus::Action::"infrastructure"],
    resource
) when {
    // EC2 compute termination
    context.command like "*aws ec2 terminate-instances*" ||
    // CloudFormation stack deletion
    context.command like "*aws cloudformation delete-stack*" ||
    // ECS cluster deletion
    context.command like "*aws ecs delete-cluster*" ||
    // RDS database instance deletion
    context.command like "*aws rds delete-db-instance*" ||
    // RDS cluster deletion
    context.command like "*aws rds delete-db-cluster*" ||
    // VPC deletion
    context.command like "*aws ec2 delete-vpc*" ||
    // Subnet deletion
    context.command like "*aws ec2 delete-subnet*" ||
    // Security group deletion
    context.command like "*aws ec2 delete-security-group*" ||
    // EKS cluster deletion
    context.command like "*aws eks delete-cluster*" ||
    // Lambda function deletion
    context.command like "*aws lambda delete-function*" ||
    // Elastic Load Balancer deletion
    context.command like "*aws elbv2 delete-load-balancer*" ||
    context.command like "*aws elb delete-load-balancer*" ||
    // Internet gateway deletion
    context.command like "*aws ec2 delete-internet-gateway*" ||
    // NAT gateway deletion
    context.command like "*aws ec2 delete-nat-gateway*"
};
// Override: context.human_approval_token must contain a valid approval reference from your
// change management system before any of the above commands will be permitted.
// Example: set context.human_approval_token = "CHANGE-12345" for approved destructive operations.
