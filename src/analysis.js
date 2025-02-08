const runRepomix = require('./repomix'); // Your repomix integration logic
const summarizeAI = require('./summarizeAI.js'); // Function that calls ChatGPT, etc.

// Main summarization function
async function summarize(repoUrl, options = {}) {
  // Run repomix to get repository analysis data
  const repomixData = await runRepomix(repoUrl, options);
  // Use your LLM key to summarize if needed
  const aiSummary = await summarizeAI(repomixData, options.llmKey);
  return {
    summary: aiSummary,
    repomixData,
  };
}

module.exports = {
  summarize,
};
