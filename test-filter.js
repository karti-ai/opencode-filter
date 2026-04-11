const { MessageFilter, SessionManager } = require('./dist/hooks.js');
const { RegexEngine } = require('./dist/patterns/regex-engine.js');
const { loadConfig } = require('./dist/config.js');
const { getBuiltinPatterns } = require('./dist/patterns/builtin.js');

async function testFilter() {
  console.log('Testing OpenCode Filter V2\n');
  
  process.env.FILTER_CONFIG_PATH = '/home/metal/repos/open-source/filter.config.json';
  const { config } = await loadConfig();
  
  console.log('Config loaded from:', process.env.FILTER_CONFIG_PATH);
  console.log('   Enabled:', config.enabled);
  console.log('   Mode:', config.mode);
  console.log('   Patterns:', config.patterns?.length || 0);
  console.log('');
  
  const sessionManager = new SessionManager();
  const sessionId = 'test-session-001';
  
  const patterns = config.patterns?.length > 0 ? config.patterns : getBuiltinPatterns();
  console.log('Using', patterns.length, 'patterns for detection\n');
  
  const regexEngine = new RegexEngine(patterns, {
    timeoutMs: 1000,
    maxFileSize: 10 * 1024 * 1024,
    cacheSize: 1000
  });
  
  const filter = new MessageFilter(regexEngine, sessionManager, config);
  
  const testCases = [
    { name: 'AWS Access Key', text: 'const apiKey = "AKIAIOSFODNN7EXAMPLE";' },
    { name: 'GitHub Token', text: 'const githubToken = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";' },
    { name: 'Stripe Live Key', text: 'const stripeKey = "sk_live_abcdefghijklmnopqrstuvwxyz1234";' },
    { name: 'Slack Token', text: 'const slackToken = "xoxb-1234567890123-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwX";' },
    { name: 'Database URL', text: 'const dbUrl = "postgres://user:password123@localhost:5432/mydb";' },
    { name: 'JWT Token', text: 'const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";' },
    { name: 'Password', text: 'const password = "MySecretPassword123!";' },
    { name: 'Normal text', text: 'const greeting = "Hello World";' }
  ];
  
  let totalSecrets = 0;
  let passed = 0;
  
  for (const test of testCases) {
    const filtered = filter.filterText(sessionId, test.text);
    const hasPlaceholder = filtered.includes('<SECRET_');
    const isNormalText = test.name === 'Normal text';
    
    let status;
    if (isNormalText) {
      status = !hasPlaceholder ? 'PASS' : 'FAIL';
      if (!hasPlaceholder) passed++;
    } else {
      status = hasPlaceholder ? 'PASS' : 'FAIL';
      if (hasPlaceholder) {
        passed++;
        totalSecrets++;
      }
    }
    
    console.log(status + ' ' + test.name);
    console.log('   Input:  ' + test.text);
    console.log('   Output: ' + filtered + '\n');
  }
  
  console.log('\nResults:');
  console.log('   Tests: ' + passed + '/' + testCases.length + ' passed');
  console.log('   Secrets filtered: ' + totalSecrets);
  
  console.log('\nTesting secret restoration:');
  const sampleInput = 'Key: AKIAIOSFODNN7EXAMPLE';
  const sampleFiltered = filter.filterText(sessionId, sampleInput);
  const sampleRestored = filter.restoreText(sessionId, sampleFiltered);
  
  console.log('   Original: ' + sampleInput);
  console.log('   Filtered: ' + sampleFiltered);
  console.log('   Restored: ' + sampleRestored);
  console.log('   Restore match: ' + (sampleInput === sampleRestored ? 'PASS' : 'FAIL'));
  
  console.log('\nFilter test complete!');
}

testFilter().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
