import { readFile, readdir } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const project = resolve(fileURLToPath(new URL('..', import.meta.url)));
const packageJson = JSON.parse(await readFile(join(project, 'package.json'), 'utf8'));
const dependencies = { ...packageJson.dependencies, ...packageJson.optionalDependencies };
const forbiddenPackages = /playwright|puppeteer|selenium|webdriver|chromium|electron|cypress|browserbase|browserless/i;
const packageViolations = Object.keys(dependencies).filter((name) => forbiddenPackages.test(name));

async function files(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await files(path));
    else if (/\.(?:mjs|js|cjs)$/.test(entry.name)) result.push(path);
  }
  return result;
}

const productionFiles = await files(join(project, 'src'));
const forbiddenRuntimePatterns = [
  { name: 'browser package import', pattern: /(?:from\s+|import\s*\()['"](?:playwright|puppeteer|selenium-webdriver|chrome-remote-interface|@browserbasehq)\b/ },
  { name: 'browser process spawn', pattern: /(?:spawn|execFile|exec)\s*\([^\n]*(?:chromium|chrome|firefox|webkit|webdriver)/i },
  { name: 'Chrome DevTools Protocol', pattern: /Page\.captureScreenshot|DOMSnapshot\.captureSnapshot|Accessibility\.getFullAXTree|connectOverCDP/ },
  { name: 'remote browser service', pattern: /(?:browserbase|browserless)\.(?:io|com)/i }
];
const sourceViolations = [];
for (const file of productionFiles) {
  const source = await readFile(file, 'utf8');
  for (const check of forbiddenRuntimePatterns) {
    if (check.pattern.test(source)) sourceViolations.push({ file: relative(project, file), rule: check.name });
  }
}

const report = {
  project: packageJson.name,
  production_dependency_count: Object.keys(dependencies).length,
  production_source_files_checked: productionFiles.map((file) => relative(project, file)),
  forbidden_package_violations: packageViolations,
  forbidden_runtime_violations: sourceViolations,
  invariant: 'No browser engine, WebDriver/CDP client, DOM/AX snapshot, renderer, or webpage screenshot runtime is present.'
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (packageViolations.length || sourceViolations.length) process.exitCode = 1;
