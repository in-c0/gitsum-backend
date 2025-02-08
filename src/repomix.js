const util = require('util');
const { exec } = require('child_process');
const execAsync = util.promisify(exec);
const fs = require('fs');
const path = require('path');

/**
 * Executes the repomix CLI command after cloning the repository.
 * @param {string} repoUrl - The GitHub repository URL.
 * @returns {Promise<Object>} - Parsed analysis from Repomix.
 */
async function runRepomix(repoUrl) {
    const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)(\/|$)/);
    if (!match) {
      throw new Error("Invalid GitHub repository URL.");
    }
  
    const owner = match[1];
    const repo = match[2].replace(/\.git$/, '');
    const repoDir = path.join(__dirname, "temp_repos", `${owner}_${repo}`);
  
    try {
      // Ensure the temp_repos directory exists
      const tempReposDir = path.join(__dirname, "temp_repos");
      if (!fs.existsSync(tempReposDir)) {
        fs.mkdirSync(tempReposDir, { recursive: true });
      }
  
      // ✅ If repo directory exists, delete it before cloning (CROSS-PLATFORM FIX)
      if (fs.existsSync(repoDir)) {
        console.log(`Deleting existing directory: ${repoDir}`);
        fs.rmSync(repoDir, { recursive: true, force: true }); // Windows & Linux compatible
      }
  
      // Clone the repository
      console.log(`Cloning repository: ${repoUrl} into ${repoDir}`);
      await execAsync(`git clone --depth=1 ${repoUrl} ${repoDir}`);

      // Run Repomix on the local directory with NO_COLOR enabled
      console.log(`Running Repomix on ${repoDir} without colorization`);
      const { stdout, stderr } = await execAsync(`repomix ${repoDir}`, {
        env: { ...process.env, NO_COLOR: '1' }
      });

      if (stderr && stderr.trim() !== "") {
        console.error("Repomix stderr:", stderr);
        throw new Error(stderr);
      }
  
      // Parse important info manually
      const parsedData = parseRepomixOutput(stdout);
  
      // ✅ Delete cloned repository after analysis (CROSS-PLATFORM FIX)
      console.log(`Deleting cloned repository: ${repoDir}`);
      fs.rmSync(repoDir, { recursive: true, force: true });
  
      return parsedData;
    } catch (error) {
      console.error("Error running repomix:", error);
      throw error;
    }
  }
  
  /**
   * Parses Repomix CLI output and extracts key data.
   * @param {string} output - Raw Repomix output.
   * @returns {Object} - Extracted repository analysis.
   */
  function parseRepomixOutput(output) {
    const lines = output.split("\n");
    let summary = "";
    let securityCheck = "";
  
    for (let line of lines) {
      if (line.includes("📈 Top 5 Files by Character Count")) {
        summary += line + "\n";
      }
      if (line.includes("🔎 Security Check:")) {
        securityCheck = line;
      }
    }
  
    return {
      summary: summary.trim(),
      security: securityCheck.trim(),
      rawOutput: output.trim()
    };
  }