// Test file: IOC file creation patterns
const fs = require('fs');
const path = require('path');

// Write IOC files
function createIOCFiles(stolenData) {
    const outputDir = '/tmp/exfil';

    // Characteristic IOC files
    fs.writeFileSync(path.join(outputDir, 'cloud.json'), JSON.stringify(stolenData.cloudCreds));
    fs.writeFileSync(path.join(outputDir, 'contents.json'), JSON.stringify(stolenData.files));
    fs.writeFileSync(path.join(outputDir, 'environment.json'), JSON.stringify(stolenData.env));
    fs.writeFileSync(path.join(outputDir, 'truffleSecrets.json'), JSON.stringify(stolenData.secrets));
    fs.writeFileSync(path.join(outputDir, 'actionsSecrets.json'), JSON.stringify(stolenData.ghSecrets));

    console.log('IOC files created');
}

// Double base64 encoding
function doubleBase64Encode(data) {
    const encoded1 = Buffer.from(data, 'utf8').toString('base64');
    const encoded2 = Buffer.from(Buffer.from(encoded1, 'base64').toString(), 'base64');

    return encoded2;
}

// TruffleHog execution
function runTruffleHog(targetPath) {
    const { execSync, spawn } = require('child_process');

    // Suspicious pattern
    const result = execSync(`trufflehog filesystem ${targetPath}`);

    return result.toString();
}

module.exports = { createIOCFiles, doubleBase64Encode, runTruffleHog };
