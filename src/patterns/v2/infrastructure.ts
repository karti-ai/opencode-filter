/**
 * Infrastructure Secret Patterns (V2)
 *
 * 30 patterns covering databases, SSH keys, SSL certificates, Docker, and Kubernetes.
 * Based on patterns from TruffleHog, GitHub Secret Scanning, and GitLeaks.
 */

import type { SecretPattern } from '../../types.js';

/**
 * Infrastructure secret patterns
 * Total: 30 patterns
 * - Database URLs: 10 patterns
 * - SSH Keys: 5 patterns
 * - SSL Certificates: 4 patterns
 * - Docker: 4 patterns
 * - Kubernetes: 7 patterns
 */
export const INFRASTRUCTURE_PATTERNS: SecretPattern[] = [
  // ============================================================================
  // Database URLs (10 patterns)
  // ============================================================================

  {
    name: 'postgres_connection_string',
    regex: /postgres(ql)?:\/\/[^:]+:[^@]+@[^/]+/i,
    category: 'connection_string',
    description: 'PostgreSQL connection string with embedded credentials',
    severity: 'critical',
    example: 'postgresql://admin:password123@localhost:5432/mydb',
  },

  {
    name: 'mysql_connection_string',
    regex: /mysql:\/\/[^:]+:[^@]+@[^/]+/i,
    category: 'connection_string',
    description: 'MySQL connection string with embedded credentials',
    severity: 'critical',
    example: 'mysql://root:secret123@localhost:3306/database',
  },

  {
    name: 'mongodb_connection_string',
    regex: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^/]+/i,
    category: 'connection_string',
    description: 'MongoDB connection string with embedded credentials',
    severity: 'critical',
    example: 'mongodb+srv://admin:password123@cluster.mongodb.net/mydb',
  },

  {
    name: 'redis_connection_string',
    regex: /redis(:\/\/|:s:\/\/)?(:?\[)?[^@]*:[^@]+@[^/]+/i,
    category: 'connection_string',
    description: 'Redis connection string with password (supports username:password or :password only)',
    severity: 'high',
    example: 'redis://:password123@localhost:6379/0',
  },

  {
    name: 'mssql_connection_string',
    regex: /(Server|Data Source)=[^;]+;.*(User Id|Uid)=[^;]+;.*(Password|Pwd)=[^;]+;/i,
    category: 'connection_string',
    description: 'Microsoft SQL Server connection string',
    severity: 'critical',
    example: 'Server=myServer;User Id=admin;Password=password123;',
  },

  {
    name: 'oracle_connection_string',
    regex: /jdbc:oracle:thin:[^/]+\/[^@]+@[^:]+:\d+:\w+/i,
    category: 'connection_string',
    description: 'Oracle JDBC connection string',
    severity: 'critical',
    example: 'jdbc:oracle:thin:admin/password123@localhost:1521:ORCL',
  },

  {
    name: 'cassandra_connection_string',
    regex: /cassandra:\/\/[^:]+:[^@]+@[^/]+/i,
    category: 'connection_string',
    description: 'Cassandra connection string with credentials',
    severity: 'high',
    example: 'cassandra://admin:password123@localhost:9042/keyspace',
  },

  {
    name: 'neo4j_connection_string',
    regex: /neo4j(\+s?[sc]?)?:\/\/[^:]+:[^@]+@[^/]+/i,
    category: 'connection_string',
    description: 'Neo4j Bolt connection string with credentials',
    severity: 'high',
    example: 'neo4j+s://neo4j:password123@localhost:7687',
  },

  {
    name: 'elasticsearch_connection_string',
    regex: /https?:\/\/[^:]+:[^@]+@elasticsearch[^/]*/i,
    category: 'connection_string',
    description: 'Elasticsearch connection string with basic auth',
    severity: 'high',
    example: 'https://elastic:password123@elasticsearch:9200',
  },

  {
    name: 'rabbitmq_connection_string',
    regex: /amqp:\/\/[^:]+:[^@]+@[^/]+/i,
    category: 'connection_string',
    description: 'RabbitMQ AMQP connection string',
    severity: 'high',
    example: 'amqp://admin:password123@localhost:5672/vhost',
  },

  // ============================================================================
  // SSH Keys (5 patterns)
  // ============================================================================

  {
    name: 'ssh_rsa_private_key',
    regex: /-----BEGIN RSA PRIVATE KEY-----/,
    category: 'private_key',
    description: 'SSH RSA Private Key',
    severity: 'critical',
    example: '-----BEGIN RSA PRIVATE KEY-----',
  },

  {
    name: 'ssh_dsa_private_key',
    regex: /-----BEGIN DSA PRIVATE KEY-----/,
    category: 'private_key',
    description: 'SSH DSA Private Key',
    severity: 'critical',
    example: '-----BEGIN DSA PRIVATE KEY-----',
  },

  {
    name: 'ssh_ecdsa_private_key',
    regex: /-----BEGIN EC PRIVATE KEY-----/,
    category: 'private_key',
    description: 'SSH ECDSA Private Key',
    severity: 'critical',
    example: '-----BEGIN EC PRIVATE KEY-----',
  },

  {
    name: 'ssh_openssh_private_key',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/,
    category: 'private_key',
    description: 'OpenSSH format Private Key',
    severity: 'critical',
    example: '-----BEGIN OPENSSH PRIVATE KEY-----',
  },

  {
    name: 'ssh_ed25519_private_key',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/,
    category: 'private_key',
    description: 'SSH Ed25519 Private Key (OpenSSH format)',
    severity: 'critical',
    example: '-----BEGIN OPENSSH PRIVATE KEY-----',
  },

  // ============================================================================
  // SSL Certificates (4 patterns)
  // ============================================================================

  {
    name: 'ssl_private_key',
    regex: /-----BEGIN PRIVATE KEY-----/,
    category: 'private_key',
    description: 'SSL/TLS Private Key (PKCS#8)',
    severity: 'critical',
    example: '-----BEGIN PRIVATE KEY-----',
  },

  {
    name: 'ssl_rsa_key',
    regex: /-----BEGIN RSA PRIVATE KEY-----/,
    category: 'private_key',
    description: 'SSL/TLS RSA Private Key (PKCS#1)',
    severity: 'critical',
    example: '-----BEGIN RSA PRIVATE KEY-----',
  },

  {
    name: 'ssl_certificate',
    regex: /-----BEGIN CERTIFICATE-----/,
    category: 'certificate',
    description: 'SSL/TLS X.509 Certificate',
    severity: 'medium',
    example: '-----BEGIN CERTIFICATE-----',
  },

  {
    name: 'ssl_pkcs12',
    regex: /-----BEGIN PKCS12-----/,
    category: 'certificate',
    description: 'PKCS#12 Certificate Bundle',
    severity: 'critical',
    example: '-----BEGIN PKCS12-----',
  },

  // ============================================================================
  // Docker (4 patterns)
  // ============================================================================

  {
    name: 'docker_config_auth',
    regex: /"auth"\s*:\s*"[a-zA-Z0-9+/]{20,}={0,2}"/,
    category: 'credential',
    description: 'Docker config.json auth token',
    severity: 'critical',
    example: '"auth": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6="',
  },

  {
    name: 'docker_hub_token',
    regex: /dckr_pat_[a-zA-Z0-9_-]{27}/,
    category: 'token',
    description: 'Docker Hub Personal Access Token',
    severity: 'critical',
    example: 'dckr_pat_a1b2c3d4e5f6g7h8i9j0k1l2m3',
  },

  {
    name: 'docker_registry_password',
    regex: /DOCKER_REGISTRY_PASSWORD\s*=\s*['"][^'"]+['"]/i,
    category: 'password',
    description: 'Docker Registry password in environment variable',
    severity: 'high',
    example: 'DOCKER_REGISTRY_PASSWORD="mypassword123"',
  },

  {
    name: 'docker_compose_secret',
    regex: /secrets:\s*\n\s*-\s*\w+:\s*\n\s*external:\s*true/,
    category: 'credential',
    description: 'Docker Compose external secret reference',
    severity: 'medium',
    example: 'secrets:\n  - my_secret:\n    external: true',
  },

  // ============================================================================
  // Kubernetes (7 patterns)
  // ============================================================================

  {
    name: 'k8s_service_account_token',
    regex: /eyJhbGciOiJSUzI1Ni[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+/,
    category: 'token',
    description: 'Kubernetes Service Account JWT Token',
    severity: 'critical',
    example: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0',
  },

  {
    name: 'k8s_secret',
    regex: /apiVersion:\s*v1\s*\nkind:\s*Secret\s*\n/,
    category: 'credential',
    description: 'Kubernetes Secret resource definition',
    severity: 'high',
    example: 'apiVersion: v1\nkind: Secret\n',
  },

  {
    name: 'k8s_docker_config_json',
    regex: /\.dockerconfigjson:\s*[a-zA-Z0-9+/]{20,}={0,2}/,
    category: 'credential',
    description: 'Kubernetes Docker config secret',
    severity: 'critical',
    example: '.dockerconfigjson: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'k8s_tls_secret',
    regex: /tls\.(crt|key):\s*[a-zA-Z0-9+/]{20,}={0,2}/,
    category: 'credential',
    description: 'Kubernetes TLS secret with certificate or key',
    severity: 'critical',
    example: 'tls.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t',
  },

  {
    name: 'k8s_basic_auth_secret',
    regex: /basic-auth\.yaml\s*\n.*username:\s*\w+\s*\n.*password:\s*\w+/,
    category: 'credential',
    description: 'Kubernetes basic-auth secret',
    severity: 'high',
    example: 'username: admin\npassword: secret123',
  },

  {
    name: 'k8s_ssh_auth_secret',
    regex: /ssh-privatekey:\s*[a-zA-Z0-9+/]{20,}={0,2}/,
    category: 'credential',
    description: 'Kubernetes SSH authentication secret',
    severity: 'critical',
    example: 'ssh-privatekey: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  },

  {
    name: 'k8s_config_file',
    regex: /current-context:\s*\w+\s*\n.*user:\s*\w+\s*\n.*client-certificate-data:/,
    category: 'credential',
    description: 'Kubernetes kubeconfig file with client certificate',
    severity: 'high',
    example: 'current-context: prod\nuser: admin\nclient-certificate-data:',
  },
];

export default INFRASTRUCTURE_PATTERNS;
