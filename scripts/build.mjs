import { build } from 'esbuild';
import { mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = (rel) => fileURLToPath(new URL(rel, import.meta.url));
const outDir = here('../dist');

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

/**
 * Bundle the whole app into one JS file, then splice it plus the stylesheet
 * into the HTML shell. The result is a single self-contained page: no external
 * requests, no sibling asset files, works from `file://` and inside a sandbox.
 */
const result = await build({
  entryPoints: [here('../web/main.tsx')],
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['es2020'],
  jsx: 'automatic',
  minify: true,
  write: false,
  loader: { '.ts': 'ts', '.tsx': 'tsx' },
  define: { 'process.env.NODE_ENV': '"production"' },
  legalComments: 'none',
});

const js = result.outputFiles[0]?.text ?? '';
if (!js) throw new Error('esbuild produced no output');
const css = readFileSync(here('../web/styles.css'), 'utf8');
const shell = readFileSync(here('../web/index.html'), 'utf8');

// Use a replacer function: the bundled JS contains `$` sequences that
// String.replace would otherwise interpret as replacement patterns.
const inlined = `<style>\n${css}\n</style>\n    <script>\n${js}\n</script>`;
const html = shell.replace(/<script type="module" src="\/main\.tsx"><\/script>/, () => inlined);

if (/<script[^>]*\ssrc=/.test(html)) {
  throw new Error('entry script was not inlined');
}
if (!html.includes(css.slice(0, 40))) {
  throw new Error('stylesheet was not inlined');
}

writeFileSync(here('../dist/index.html'), html);
console.log(`dist/index.html  ${(html.length / 1024).toFixed(1)} kB`);
