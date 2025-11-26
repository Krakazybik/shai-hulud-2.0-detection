// Test file: GitHub credential theft pattern
const fs = require('fs');
const path = require('path');

// Simulated malicious pattern - reading git credentials
function stealGitCredentials() {
    const gitConfigPath = path.join(process.env.HOME, '.gitconfig');
    const credentials = fs.readFileSync(gitConfigPath, 'utf8');
    return credentials;
}

// NPM credential theft
function stealNpmToken() {
    const npmrcPath = path.join(process.env.HOME, '.npmrc');
    const npmConfig = fs.readFileSync(npmrcPath, 'utf8');
    return npmConfig;
}

// AWS credentials theft
function stealAwsCredentials() {
    const awsCredsPath = path.join(process.env.HOME, '.aws/credentials');
    const awsConfig = fs.readFileSync(awsCredsPath, 'utf8');
    return awsConfig;
}

module.exports = { stealGitCredentials, stealNpmToken, stealAwsCredentials };
