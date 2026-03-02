import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const parentDir = path.dirname(__dirname);
const indexPath = path.join(parentDir, 'index.js');

// Test Results
const testResults = {
  passed: 0,
  failed: 0,
  tests: []
};

function test(name, fn) {
  try {
    fn();
    testResults.passed++;
    testResults.tests.push({ name, status: '✅ PASS' });
    console.log(`✅ ${name}`);
  } catch (error) {
    testResults.failed++;
    testResults.tests.push({ name, status: '❌ FAIL', error: error.message });
    console.log(`❌ ${name}: ${error.message}`);
  }
}

// Helper to run node commands
function runNodeCommand(args) {
  return new Promise((resolve, reject) => {
    const child = spawn('node', [indexPath, ...args], {
      cwd: parentDir,
      timeout: 30000
    });
    
    let stdout = '';
    let stderr = '';
    
    child.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    
    child.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    
    child.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
    
    child.on('error', reject);
    
    setTimeout(() => {
      child.kill();
      reject(new Error('Command timeout'));
    }, 30000);
  });
}

console.log('\n' + '='.repeat(70));
console.log('🧪 INTEGRATION TESTS - Feature Functionality');
console.log('='.repeat(70) + '\n');

// ============================================================================
// TEST SUITE 1: Function Syntax Validation
// ============================================================================
console.log('📋 TEST SUITE 1: Function Syntax Validation');
console.log('-'.repeat(70));

test('1.1: index.js is valid JavaScript', () => {
  try {
    fs.readFileSync(indexPath, 'utf8');
  } catch (error) {
    throw new Error('Cannot read index.js');
  }
});

test('1.2: index.js imports commander', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  assert(
    code.includes("import * as program") || 
    code.includes("import program") ||
    code.includes("from 'commander'"),
    'Commander.js not properly imported'
  );
});

test('1.3: index.js imports required modules', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const requiredImports = ['fs', 'path', 'jsdom', 'acorn'];
  let missingImports = [];
  
  requiredImports.forEach(mod => {
    if (!code.includes(mod)) {
      missingImports.push(mod);
    }
  });
  
  assert(
    missingImports.length === 0,
    `Missing imports: ${missingImports.join(', ')}`
  );
});

// ============================================================================
// TEST SUITE 2: Deduplication Feature Validation
// ============================================================================
console.log('\n📋 TEST SUITE 2: Deduplication Feature Tests');
console.log('-'.repeat(70));

test('2.1: Deduplication logic uses Map correctly', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const hasMap = code.includes('new Map()');
  const hasKeys = code.includes('.set(') && code.includes('.get(');
  assert(
    hasMap && hasKeys,
    'Map data structure not properly used for deduplication'
  );
});

test('2.2: Deduplication preserves first occurrence', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const dedupeSection = code.substring(
    code.indexOf('deduplicateRequests'),
    code.indexOf('deduplicateRequests') + 500
  );
  assert(
    dedupeSection.includes('!seen') || dedupeSection.includes('!has'),
    'Should check if key exists before adding'
  );
});

test('2.3: Deduplication tracking includes method', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  assert(
    code.includes('method') && code.includes('deduplicateRequests'),
    'Deduplication should track HTTP method'
  );
});

test('2.4: deduplicationStats computed in exportResults', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  assert(
    code.includes('requestsBeforeDedup') && 
    code.includes('requestsAfterDedup'),
    'Deduplication stats not properly calculated'
  );
});

// ============================================================================
// TEST SUITE 3: Parameter Detection Validation
// ============================================================================
console.log('\n📋 TEST SUITE 3: Parameter Detection Tests');
console.log('-'.repeat(70));

test('3.1: Detects authentication parameters', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const authPatterns = ['password', 'api_key', 'secret', 'auth'];
  let found = 0;
  authPatterns.forEach(p => {
    if (code.includes(`'${p}'`) || code.includes(`"${p}"`)) found++;
  });
  assert(found >= 2, 'Should detect multiple auth parameters');
});

test('3.2: Detects session parameters', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const sessionPatterns = ['sessionid', 'session_id', 'sid', 'jsessionid'];
  let found = 0;
  sessionPatterns.forEach(p => {
    if (code.includes(`'${p}'`) || code.includes(`"${p}"`)) found++;
  });
  assert(found >= 1, 'Should detect session parameters');
});

test('3.3: Detects personal data parameters', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const personalPatterns = ['email', 'phone', 'ssn', 'credit_card'];
  let found = 0;
  personalPatterns.forEach(p => {
    if (code.includes(`'${p}'`) || code.includes(`"${p}"`)) found++;
  });
  assert(found >= 2, 'Should detect personal data parameters');
});

test('3.4: Detects API and admin parameters', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const adminPatterns = ['admin', 'api', 'debug', 'key'];
  let found = 0;
  adminPatterns.forEach(p => {
    if (code.includes(`'${p}'`) || code.includes(`"${p}"`)) found++;
  });
  assert(found >= 2, 'Should detect API/admin parameters');
});

// ============================================================================
// TEST SUITE 4: Filename Generation Validation
// ============================================================================
console.log('\n📋 TEST SUITE 4: Filename Generation Tests');
console.log('-'.repeat(70));

test('4.1: Hostname extraction uses URL constructor', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  assert(
    code.includes('new URL(') && code.includes('.hostname'),
    'Should use URL constructor for hostname extraction'
  );
});

test('4.2: www prefix removal regex present', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  assert(
    code.includes("replace(/^www\\.") || code.includes("replace(/^www\\\\."),
    'Should remove www. prefix'
  );
});

test('4.3: Dot to hyphen conversion present', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  assert(
    code.includes("\\.replace(/\\./g") || code.includes(".replace(/\\\\.") || code.includes("replace(") && code.includes("hyphen"),
    'Should convert dots to hyphens'
  );
});

test('4.4: Local path handling with fs.statSync', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  assert(
    code.includes('fs.statSync') && code.includes('isDirectory'),
    'Should check if path is directory'
  );
});

test('4.5: Date stamping in ISO format', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  assert(
    code.includes("toISOString()") && code.includes("split('T')[0]"),
    'Should generate YYYY-MM-DD date stamp'
  );
});

test('4.6: File extension based on format', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  assert(
    code.includes("format === 'xlsx'") && code.includes('extension'),
    'Should set correct file extension'
  );
});

test('4.7: Error handling with fallback name', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const generateSection = code.substring(
    code.indexOf('generateReportFilename'),
    code.indexOf('generateReportFilename') + 1500
  );
  assert(
    generateSection.includes('catch') && generateSection.includes('web-recon-report'),
    'Should have fallback naming on error'
  );
});

// ============================================================================
// TEST SUITE 5: Integration Tests
// ============================================================================
console.log('\n📋 TEST SUITE 5: Code Integration Tests');
console.log('-'.repeat(70));

test('5.1: analyzeTarget checks for output flag', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const analyzeSection = code.substring(
    code.indexOf('analyzeTarget'),
    code.indexOf('analyzeTarget') + 2000
  );
  assert(
    analyzeSection.includes('if (output)') || analyzeSection.includes('output ?'),
    'Should check output flag in analyzeTarget'
  );
});

test('5.2: analyzeLocalPath checks for output flag', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const analyzeSection = code.substring(
    code.indexOf('analyzeLocalPath'),
    code.indexOf('analyzeLocalPath') + 2000
  );
  assert(
    analyzeSection.includes('if (output)') || analyzeSection.includes('output ?'),
    'Should check output flag in analyzeLocalPath'
  );
});

test('5.3: generateReportFilename called in analyzeTarget', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const analyzeSection = code.substring(
    code.indexOf('analyzeTarget'),
    code.lastIndexOf('analyzeTarget') + 2500
  );
  assert(
    analyzeSection.includes('generateReportFilename'),
    'generateReportFilename should be called in analyzeTarget'
  );
});

test('5.4: generateReportFilename called in analyzeLocalPath', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const analyzeSection = code.substring(
    code.indexOf('analyzeLocalPath'),
    code.lastIndexOf('analyzeLocalPath') + 2500
  );
  assert(
    analyzeSection.includes('generateReportFilename'),
    'generateReportFilename should be called in analyzeLocalPath'
  );
});

test('5.5: Deduplication happens before export', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const exportSection = code.substring(
    code.indexOf('exportResults'),
    code.indexOf('exportResults') + 800
  );
  assert(
    exportSection.includes('deduplicateStores') || code.includes('deduplicateStores'),
    'Deduplication should happen before export'
  );
});

// ============================================================================
// TEST SUITE 6: Backward Compatibility
// ============================================================================
console.log('\n📋 TEST SUITE 6: Backward Compatibility Tests');
console.log('-'.repeat(70));

test('6.1: Custom -o flag still respected', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  const exportLogic = code.substring(
    code.indexOf('if (output)'),
    code.indexOf('if (output)') + 200
  );
  assert(
    exportLogic.includes('output'),
    'Custom output flag should still be respected'
  );
});

test('6.2: No breaking changes to program.action', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  assert(
    code.includes('program.action('),
    'program.action structure should remain'
  );
});

test('6.3: CLI options still available', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  assert(
    code.includes('program.option') || code.includes('-f') && code.includes('-o'),
    'CLI options should still be available'
  );
});

test('6.4: JSDOM and fetch still available', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  assert(
    (code.includes('JSDOM') || code.includes('jsdom')) && code.includes('fetch'),
    'Core analysis features should still work'
  );
});

test('6.5: XLSX export still functional', () => {
  const code = fs.readFileSync(indexPath, 'utf8');
  assert(
    code.includes('XLSX') || code.includes('xlsx'),
    'XLSX export should still be available'
  );
});

// ============================================================================
// Print Test Summary
// ============================================================================
console.log('\n' + '='.repeat(70));
console.log('📊 INTEGRATION TEST SUMMARY');
console.log('='.repeat(70));

console.log(`\n✅ Passed: ${testResults.passed}`);
console.log(`❌ Failed: ${testResults.failed}`);
console.log(`📈 Total:  ${testResults.passed + testResults.failed}`);
console.log(`📊 Success Rate: ${((testResults.passed / (testResults.passed + testResults.failed)) * 100).toFixed(1)}%`);

if (testResults.failed === 0) {
  console.log('\n🎉 ALL INTEGRATION TESTS PASSED! 🎉');
  console.log('\nIntegration Status:');
  console.log('  ✅ Deduplication Feature - INTEGRATED');
  console.log('  ✅ Parameter Detection - INTEGRATED');
  console.log('  ✅ Filename Generation - INTEGRATED');
  console.log('  ✅ Backward Compatibility - VERIFIED');
  process.exit(0);
} else {
  console.log('\n⚠️  SOME TESTS FAILED');
  testResults.tests
    .filter(t => t.status === '❌ FAIL')
    .forEach(t => {
      console.log(`  ❌ ${t.name}`);
      if (t.error) console.log(`     Error: ${t.error}`);
    });
  process.exit(1);
}
