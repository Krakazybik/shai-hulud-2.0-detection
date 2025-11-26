// Clean test file: Legitimate configuration reading
const fs = require('fs');
const path = require('path');

// Legitimate config reading
function loadAppConfig() {
    const configPath = path.join(__dirname, 'config.json');

    if (fs.existsSync(configPath)) {
        const config = fs.readFileSync(configPath, 'utf8');
        return JSON.parse(config);
    }

    return getDefaultConfig();
}

// Read user preferences (not credentials)
function loadUserPreferences() {
    const prefsPath = path.join(process.env.HOME, '.myapp', 'preferences.json');

    try {
        const prefs = fs.readFileSync(prefsPath, 'utf8');
        return JSON.parse(prefs);
    } catch (error) {
        return {};
    }
}

// Legitimate environment variable usage
function getConfig() {
    return {
        port: process.env.PORT || 3000,
        nodeEnv: process.env.NODE_ENV || 'development',
        logLevel: process.env.LOG_LEVEL || 'info'
    };
}

function getDefaultConfig() {
    return {
        apiUrl: 'https://api.example.com',
        timeout: 5000
    };
}

module.exports = { loadAppConfig, loadUserPreferences, getConfig };
