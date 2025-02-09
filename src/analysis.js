// src/analysis.js
const axios = require('axios');

// the base URL of backend API (ensure this is accessible over HTTPS)
const API_BASE_URL = process.env.API_BASE_URL || 'https://gitsum.xyz';

function validateLicense(licenseKey) {
  return axios
    .post(`${API_BASE_URL}/api/license/validate`, { licenseKey })
    .then(response => response.data);
}

function summarizeRepo(repoUrl, token) {
  return axios
    .post(
      `${API_BASE_URL}/summarize`,
      { repoUrl },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      }
    )
    .then(response => response.data);
}

function getDashboard(token) {
  return axios
    .get(`${API_BASE_URL}/dashboard`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    .then(response => response.data);
}

function getFileTree(repoUrl, branch, token) {
  return axios
    .get(`${API_BASE_URL}/filetree`, {
      params: { repoUrl, branch },
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    .then(response => response.data);
}

module.exports = { validateLicense, summarizeRepo, getDashboard, getFileTree };
