// Example from src/analysis.js
const summarizeAI = require('./summarizeAI');

async function summarize(repoUrl, options = {}) {
  const repomixData = await runRepomix(repoUrl, options); // Your repomix integration
  const aiSummary = await summarizeAI(repomixData, options.llmKey);
  return {
    summary: aiSummary,
    repomixData,
  };
}

module.exports = { summarize };
