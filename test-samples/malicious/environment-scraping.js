// Test file: Environment variable scraping
const fs = require('fs');

// Mass environment variable extraction
function scrapeEnvironment() {
    // Collect all environment variables
    const allEnv = JSON.stringify(process.env);

    // Alternative methods
    const envKeys = Object.keys(process.env);
    const envEntries = Object.entries(process.env);

    return {
        all: allEnv,
        keys: envKeys,
        entries: envEntries
    };
}

// Detect CI environment
function detectCIEnvironment() {
    if (process.env.GITHUB_ACTIONS || process.env.CI) {
        // Synchronous execution in CI
        console.log('Running in CI environment');
        return 'ci';
    } else if (process.env.BUILDKITE || process.env.CODEBUILD_BUILD_NUMBER) {
        // Different CI providers
        return 'ci-other';
    } else if (process.env.CIRCLE_SHA1) {
        return 'circleci';
    } else {
        // Asynchronous execution on dev machines
        setTimeout(() => {
            console.log('Running on dev machine');
        }, 5000);
        return 'dev';
    }
}

// Datadog credentials
function stealDatadogCreds() {
    const ddApiKey = process.env.DD_API_KEY;
    const ddAppKey = process.env.DD_APP_KEY;
    const datadogKey = process.env.DATADOG_API_KEY;

    return { ddApiKey, ddAppKey, datadogKey };
}

module.exports = { scrapeEnvironment, detectCIEnvironment, stealDatadogCreds };
