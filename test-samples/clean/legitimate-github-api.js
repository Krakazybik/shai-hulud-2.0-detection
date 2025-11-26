// Clean test file: Legitimate GitHub API usage
const axios = require('axios');

// Legitimate GitHub API usage for fetching public data
async function getRepositoryInfo(owner, repo) {
    const response = await axios.get(
        `https://api.github.com/repos/${owner}/${repo}`,
        {
            headers: {
                'Accept': 'application/vnd.github.v3+json'
            }
        }
    );

    return response.data;
}

// Fetch public user information
async function getUserInfo(username) {
    const response = await axios.get(
        `https://api.github.com/users/${username}`,
        {
            headers: {
                'Accept': 'application/vnd.github.v3+json'
            }
        }
    );

    return response.data;
}

// Search repositories
async function searchRepositories(query) {
    const response = await axios.get(
        `https://api.github.com/search/repositories`,
        {
            params: { q: query },
            headers: {
                'Accept': 'application/vnd.github.v3+json'
            }
        }
    );

    return response.data;
}

module.exports = { getRepositoryInfo, getUserInfo, searchRepositories };
