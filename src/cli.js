#!/usr/bin/env node
const { program } = require('commander');
const inquirer = require('inquirer');
const api = require('./api');
const { loadConfig, saveConfig } = require('./config');

program.version('1.0.0');

// Login command: prompts user for license key, validates it via the backend,
// and stores the key and returned JWT token locally.
program
  .command('login')
  .description('Log in with your license key')
  .action(async () => {
    try {
      const answers = await inquirer.prompt([
        { type: 'input', name: 'licenseKey', message: 'Enter your license key:' }
      ]);

      const result = await api.validateLicense(answers.licenseKey);
      if (result.valid) {
        // Save license details (and token) locally for subsequent API calls.
        const config = loadConfig();
        config.licenseKey = answers.licenseKey;
        config.token = result.token; // Assuming your backend returns a JWT token.
        config.plan = result.plan;
        config.usageCount = result.usageCount;
        config.monthlyUsageLimit = result.monthlyUsageLimit;
        config.repoRestrictions = result.repoRestrictions;
        saveConfig(config);
        console.log('License validated and saved successfully!');
      } else {
        console.error('License validation failed:', result.error);
      }
    } catch (err) {
      console.error('Error during license validation:', err.message);
    }
  });

// Summarize command: calls the /summarize endpoint with the given repo URL.
program
  .command('summarize <repoUrl>')
  .description('Generate a summary for the specified repository')
  .action(async (repoUrl) => {
    const config = loadConfig();
    if (!config.token) {
      console.error('You must log in first using "gitsum login".');
      process.exit(1);
    }
    try {
      const summaryData = await api.summarizeRepo(repoUrl, config.token);
      console.log('Summary:');
      console.log(summaryData.summary);
    } catch (err) {
      console.error('Error during summarization:', err.message);
    }
  });

// Dashboard command: retrieves current usage and plan details.
program
  .command('dashboard')
  .description('Show current usage and plan details')
  .action(async () => {
    const config = loadConfig();
    if (!config.token) {
      console.error('You must log in first using "gitsum login".');
      process.exit(1);
    }
    try {
      const dashboard = await api.getDashboard(config.token);
      console.log('Dashboard:');
      console.log(dashboard);
    } catch (err) {
      console.error('Error retrieving dashboard:', err.message);
    }
  });

// File tree command: retrieves the file tree for the given repository.
program
  .command('filetree <repoUrl>')
  .option('-b, --branch <branch>', 'Specify branch', 'main')
  .description('Retrieve the file tree for the specified repository')
  .action(async (repoUrl, options) => {
    const config = loadConfig();
    if (!config.token) {
      console.error('You must log in first using "gitsum login".');
      process.exit(1);
    }
    try {
      const tree = await api.getFileTree(repoUrl, options.branch, config.token);
      console.log('File Tree:');
      console.log(JSON.stringify(tree, null, 2));
    } catch (err) {
      console.error('Error retrieving file tree:', err.message);
    }
  });

program.parse(process.argv);
