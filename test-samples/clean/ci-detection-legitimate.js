// Clean test file: Legitimate CI detection for build optimization
const { execSync } = require('child_process');

// Legitimate use: Adjust build behavior based on environment
function configureBuild() {
    const isCI = process.env.CI === 'true';

    const config = {
        cache: !isCI, // Disable cache in CI for fresh builds
        parallel: isCI ? 4 : 2, // More parallelism in CI
        verbose: isCI // More verbose output in CI
    };

    return config;
}

// Legitimate use: Different test reporters for CI vs local
function getTestConfig() {
    if (process.env.GITHUB_ACTIONS) {
        return {
            reporter: 'github-actions',
            coverage: true
        };
    }

    if (process.env.CI) {
        return {
            reporter: 'junit',
            coverage: true
        };
    }

    return {
        reporter: 'spec',
        coverage: false
    };
}

// Legitimate use: Platform-specific commands
function runBuild() {
    const buildCommand = process.platform === 'win32'
        ? 'npm.cmd run build'
        : 'npm run build';

    execSync(buildCommand, { stdio: 'inherit' });
}

module.exports = { configureBuild, getTestConfig, runBuild };
