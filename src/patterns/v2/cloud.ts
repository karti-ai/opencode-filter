/**
 * Cloud Provider Secret Patterns (V2)
 *
 * 30 patterns covering AWS, Azure, and GCP services.
 * Based on patterns from TruffleHog, GitHub Secret Scanning, and GitLeaks.
 */

import type { SecretPattern } from '../../types.js';

/**
 * Cloud provider secret patterns
 * Total: 30 patterns
 * - AWS: 15 patterns
 * - Azure: 8 patterns
 * - GCP: 7 patterns
 */
export const CLOUD_PATTERNS: SecretPattern[] = [
  // ============================================================================
  // AWS (15 patterns)
  // ============================================================================

  {
    name: 'aws_access_key_id',
    regex: /AKIA[0-9A-Z]{16}/,
    category: 'credential',
    description: 'AWS Access Key ID starting with AKIA',
    severity: 'critical',
    example: 'AKIAIOSFODNN7EXAMPLE',
  },

  {
    name: 'aws_secret_access_key',
    regex: /[0-9a-zA-Z/+]{40}/,
    category: 'credential',
    description: 'AWS Secret Access Key (40-character base64-like string)',
    severity: 'critical',
    example: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  },

  {
    name: 'aws_session_token',
    regex: /FwoGZXIvYXdzEBYaDG[A-Za-z0-9/+=]{100,}/,
    category: 'token',
    description: 'AWS Session Token (temporary credentials)',
    severity: 'critical',
    example: 'FwoGZXIvYXdzEBYaDGabcdefghij1234567890',
  },

  {
    name: 'aws_mws_auth_token',
    regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/,
    category: 'token',
    description: 'Amazon MWS Auth Token',
    severity: 'critical',
    example: 'amzn.mws.a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6',
  },

  {
    name: 'aws_s3_access_key',
    regex: /AKIA[0-9A-Z]{16}/,
    category: 'credential',
    description: 'AWS S3 Access Key ID',
    severity: 'critical',
    example: 'AKIAIOSFODNN7EXAMPLE',
  },

  {
    name: 'aws_iam_user_key',
    regex: /AKIA[0-9A-Z]{16}/,
    category: 'credential',
    description: 'AWS IAM User Access Key',
    severity: 'critical',
    example: 'AKIAIOSFODNN7EXAMPLE',
  },

  {
    name: 'aws_rds_password',
    regex: /rds[a-z0-9]*:\/\/[^:]+:[^@]+@[^/]+/i,
    category: 'connection_string',
    description: 'AWS RDS connection string with credentials',
    severity: 'critical',
    example: 'rds://admin:password123@mydb.cluster-xyz.us-east-1.rds.amazonaws.com:5432/mydb',
  },

  {
    name: 'aws_lambda_env_var',
    regex: /AWS_LAMBDA_[A-Z_]+_KEY\s*[=:]\s*['"][a-zA-Z0-9+/=]{20,}['"]/,
    category: 'environment_variable',
    description: 'AWS Lambda environment variable with API key',
    severity: 'high',
    example: 'AWS_LAMBDA_API_KEY="a1b2c3d4e5f6g7h8i9j0"',
  },

  {
    name: 'aws_api_gateway_key',
    regex: /[a-zA-Z0-9]{40}/,
    category: 'api_key',
    description: 'AWS API Gateway API Key (40-character string)',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
  },

  {
    name: 'aws_cognito_key',
    regex: /[a-z0-9]{26}/,
    category: 'api_key',
    description: 'AWS Cognito App Client Secret',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m',
  },

  {
    name: 'aws_cloudfront_key',
    regex: /[a-zA-Z0-9+/]{40}/,
    category: 'private_key',
    description: 'AWS CloudFront Private Key',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
  },

  {
    name: 'aws_dynamodb_key',
    regex: /dynamodb[a-z0-9]*:\/\/[^:]+:[^@]+/i,
    category: 'connection_string',
    description: 'AWS DynamoDB connection string with credentials',
    severity: 'critical',
    example: 'dynamodb://AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI@dynamodb.us-east-1.amazonaws.com',
  },

  {
    name: 'aws_elasticache_key',
    regex: /[a-f0-9]{32}/,
    category: 'credential',
    description: 'AWS ElastiCache authentication token',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'aws_secrets_manager_arn',
    regex: /arn:aws:secretsmanager:[a-z0-9-]+:\d+:secret:[a-zA-Z0-9/_+=.@~-]+/,
    category: 'credential',
    description: 'AWS Secrets Manager ARN reference',
    severity: 'medium',
    example: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-AbCdEf',
  },

  {
    name: 'aws_kinesis_key',
    regex: /kinesis[a-z0-9]*:\/\/[^:]+:[^@]+/i,
    category: 'connection_string',
    description: 'AWS Kinesis connection string with credentials',
    severity: 'high',
    example: 'kinesis://AKIAIOSFODNN7EXAMPLE:secret@kinesis.us-east-1.amazonaws.com',
  },

  // ============================================================================
  // Azure (8 patterns)
  // ============================================================================

  {
    name: 'azure_subscription_key',
    regex: /[a-f0-9]{32}/,
    category: 'credential',
    description: 'Azure Subscription Key (32-character hex string)',
    severity: 'high',
    example: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
  },

  {
    name: 'azure_storage_account_key',
    regex: /[a-zA-Z0-9+/]{86}==/,
    category: 'credential',
    description: 'Azure Storage Account Key (base64, ends with ==)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8==',
  },

  {
    name: 'azure_service_principal_secret',
    regex: /[a-zA-Z0-9_-]{40,50}/,
    category: 'credential',
    description: 'Azure Service Principal Client Secret',
    severity: 'critical',
    example: 'a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6',
  },

  {
    name: 'azure_devops_pat',
    regex: /[a-z0-9]{52}/,
    category: 'token',
    description: 'Azure DevOps Personal Access Token (52-character string)',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6',
  },

  {
    name: 'azure_cosmosdb_key',
    regex: /[a-zA-Z0-9]{86}==/,
    category: 'credential',
    description: 'Azure Cosmos DB Primary/Secondary Key',
    severity: 'critical',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8==',
  },

  {
    name: 'azure_sql_connection_string',
    regex: /Server=tcp:[^;]+;Database=[^;]+;User\s*ID=[^;]+;Password=[^;]+;/i,
    category: 'connection_string',
    description: 'Azure SQL Database connection string with password',
    severity: 'critical',
    example: 'Server=tcp:myserver.database.windows.net;Database=mydb;User ID=admin;Password=MyP@ssw0rd!;',
  },

  {
    name: 'azure_key_vault_secret',
    regex: /https:\/\/[a-z0-9-]+\.vault\.azure\.net\/secrets\/[a-zA-Z0-9-]+\/[a-z0-9]+/,
    category: 'credential',
    description: 'Azure Key Vault secret URL',
    severity: 'high',
    example: 'https://my-keyvault.vault.azure.net/secrets/my-secret/a1b2c3d4e5f6g7h8',
  },

  {
    name: 'azure_app_service_key',
    regex: /[a-zA-Z0-9_-]{40}/,
    category: 'credential',
    description: 'Azure App Service deployment key',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
  },

  // ============================================================================
  // GCP (7 patterns)
  // ============================================================================

  {
    name: 'gcp_api_key',
    regex: /AIza[0-9A-Za-z_-]{35}/,
    category: 'api_key',
    description: 'Google Cloud Platform API Key starting with AIza',
    severity: 'high',
    example: 'AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI',
  },

  {
    name: 'gcp_oauth_access_token',
    regex: /ya29\.[0-9A-Za-z_-]+/,
    category: 'token',
    description: 'Google OAuth 2.0 Access Token starting with ya29',
    severity: 'critical',
    example: 'ya29.a0Aa4b16C3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0',
  },

  {
    name: 'gcp_service_account_key',
    regex: /"type":\s*"service_account"/,
    category: 'private_key',
    description: 'GCP Service Account JSON key file',
    severity: 'critical',
    example: '{"type": "service_account", "project_id": "my-project"}',
  },

  {
    name: 'gcp_firebase_api_key',
    regex: /AIza[0-9A-Za-z_-]{35}/,
    category: 'api_key',
    description: 'Firebase API Key (Google Cloud)',
    severity: 'high',
    example: 'AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI',
  },

  {
    name: 'gcp_storage_hmac_key',
    regex: /GOOG[0-9A-Za-z_-]{40}/,
    category: 'credential',
    description: 'Google Cloud Storage HMAC key',
    severity: 'critical',
    example: 'GOOG1aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
  },

  {
    name: 'gcp_pubsub_key',
    regex: /[a-z0-9]{26}/,
    category: 'credential',
    description: 'GCP Pub/Sub service account key',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m',
  },

  {
    name: 'gcp_bigquery_key',
    regex: /[a-z0-9]{39}/,
    category: 'credential',
    description: 'GCP BigQuery API key',
    severity: 'high',
    example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s',
  },
];

export default CLOUD_PATTERNS;
