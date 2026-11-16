import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const yaml = readFileSync(fileURLToPath(new URL('../fixtures/cluster.yaml', import.meta.url)), 'utf8');
const out = `// Generated from fixtures/cluster.yaml by scripts/emit-demo.mjs — do not edit.
export const DEMO_YAML = ${JSON.stringify(yaml)};
`;
writeFileSync(fileURLToPath(new URL('../web/demoData.ts', import.meta.url)), out);
console.log('wrote web/demoData.ts');
