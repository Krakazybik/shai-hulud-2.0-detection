// Test file: Destructive behavior patterns
const fs = require('fs');
const { execSync } = require('child_process');
const path = require('path');

// Home directory destruction
function destroyHomeDirectory() {
    const homeDir = process.env.HOME;

    // Dangerous patterns - DO NOT RUN
    // fs.rmSync(homeDir, { recursive: true, force: true });
    // fs.rmdirSync(homeDir, { recursive: true });
    // execSync('rm -rf $HOME');

    console.log('Destructive function - NOT EXECUTED');
}

// Docker privilege escalation
function dockerPrivilegeEscalation() {
    const command = 'docker run --privileged -v /:/host ubuntu bash -c "cp /host/tmp/runner /host/etc/sudoers.d/runner"';

    // Dangerous - DO NOT RUN
    // execSync(command);

    console.log('Docker escalation pattern - NOT EXECUTED');
}

// Bun runtime installation
function installBunRuntime() {
    const installCommand = 'curl https://bun.sh/install | bash';

    // Suspicious pattern
    // execSync(installCommand);

    console.log('Bun install pattern detected');
}

// Automated npm publish in loop
function autoPublishPackages() {
    const packages = ['pkg1', 'pkg2', 'pkg3'];

    for (const pkg of packages) {
        // Suspicious pattern
        // execSync('npm publish');
        console.log(`Would publish: ${pkg}`);
    }
}

module.exports = { destroyHomeDirectory, dockerPrivilegeEscalation, installBunRuntime, autoPublishPackages };
