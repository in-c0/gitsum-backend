#!/usr/bin/env node
const { program } = require('commander');
const { login, validateLicense } = require('./license');
const { summarize } = require('./analysis');
const pkg = require('../package.json');

// Define the version from package.json
program.version(pkg.version);

// Command to log in and store license key locally
program
  .command('login')
  .description('Log in and set your license key')
  .action(async () => {
    try {
      // Prompt the user for their license key (you could use readline or inquirer)
      const readline = require('readline');
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });
      rl.question('Enter your license key: ', async (licenseKey) => {
        rl.close();
        // Validate the license key with your license server
        const valid = await validateLicense(licenseKey);
        if (valid) {
          // Save the license key to a config file (e.g., ~/.gitsum/config.json)
          const os = require('os');
          const fs = require('fs');
          const configDir = `${os.homedir()}/.gitsum`;
          if (!fs.existsSync(configDir)) {
            fs.mkdirSync(configDir, { recursive: true });
          }
          fs.writeFileSync(`${configDir}/config.json`, JSON.stringify({ licenseKey }, null, 2));
          console.log('License key saved successfully!');
        } else {
          console.error('Invalid license key. Please try again.');
        }
      });
    } catch (err) {
      console.error('Error during login:', err.message);
    }
  });

// Command to summarize a repository
program
  .command('summarize <repoUrl>')
  .description('Generate a summary of the specified repository')
  .option('--llm <key>', 'Supply your own LLM API key if not set in the environment')
  .action(async (repoUrl, options) => {
    try {
      // Read the saved license key from config file
      const os = require('os');
      const fs = require('fs');
      const configPath = `${os.homedir()}/.gitsum/config.json`;
      if (!fs.existsSync(configPath)) {
        console.error('You must run "gitsum login" first to set your license key.');
        process.exit(1);
      }
      const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      // Validate the license before processing
      const valid = await validateLicense(config.licenseKey);
      if (!valid) {
        console.error('Your license key is invalid or expired. Please login again.');
        process.exit(1);
      }
      // Pass the repository URL and LLM key (if provided) to your summarization function
      const summaryResult = await summarize(repoUrl, { llmKey: options.llm || process.env.OPENAI_API_KEY });
      console.log(JSON.stringify(summaryResult, null, 2));
    } catch (err) {
      console.error('Error during summarization:', err.message);
    }
  });

program.parse(process.argv);
