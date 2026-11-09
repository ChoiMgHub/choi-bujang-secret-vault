import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test } from 'node:test';

const baseline = JSON.parse(await readFile(new URL('../package/baseline-functions.json', import.meta.url)));

test('시작 틀의 API 기준표를 보존하고 메모·공지·강사 자료·지정 메모 복구 경로를 추가한다', async () => {
  const actual = (await readdir(new URL('../api/', import.meta.url)))
    .filter(name => /\.(?:m?js|ts)$/u.test(name))
    .map(name => join('api', name).replaceAll('\\', '/')).sort();
  assert.equal(baseline.version, 1);
  assert.equal(baseline.starter, 'ChoiTimo/aleph-defense-starter');
  assert.deepEqual(baseline.functions, []);
  assert.deepEqual(baseline.allowedNew, ['api/ai.js', 'api/threat-intel.js']);
  assert.deepEqual(actual, [...baseline.functions, 'api/[feature].js',
    'api/notes.js', 'api/auth.js', 'api/device.js', 'api/notices.js', 'api/instructor.js', 'api/restore.js'].sort());
  const dynamic = await readFile(new URL('../api/notes/[id].js', import.meta.url), 'utf8');
  assert.match(dynamic, /export \{ default \} from '\.\.\/notes\.js'/u);
  for (const name of ['notices', 'instructor']) {
    const resource = await readFile(new URL(`../api/${name}/[id].js`, import.meta.url), 'utf8');
    assert.ok(resource.includes(`export { default } from '../${name}.js'`));
  }
  const management = await readFile(new URL('../api/admin/notices.js', import.meta.url), 'utf8');
  assert.match(management, /area: 'notices', admin: true/u);
  const managementItem = await readFile(new URL('../api/admin/notices/[id].js', import.meta.url), 'utf8');
  assert.ok(managementItem.includes("export { default } from '../notices.js'"));
});

test('미구현 서버 뼈대는 성공이나 로그인 통과로 가장하지 않는다', async () => {
  for (const name of ['ai', 'threat-intel']) {
    const { default: handler } = await import('../api/[feature].js');
    const headers = new Map();
    let status;
    let body;
    handler({ url: `/api/${name}` }, {
      setHeader: (key, value) => headers.set(key.toLowerCase(), value),
      status: value => { status = value; return { json: value => { body = value; } }; },
    });
    assert.equal(status, 501);
    assert.equal(headers.get('cache-control'), 'no-store');
    assert.match(body.error, /NOT_IMPLEMENTED$/u);
  }
});

test('P7 시작 틀 안내는 실제 빌드 조건과 새 배포 시험에 맞는다', async () => {
  const readme = await readFile(new URL('../package/README.md', import.meta.url), 'utf8');
  const selfCheck = await readFile(new URL('../package/SELF-CHECK.md', import.meta.url), 'utf8');
  assert.match(readme, /새 Vercel 프로젝트/u);
  assert.match(readme, /Vercel이 제공하는 저장소·커밋·배포 URL 정보/u);
  assert.doesNotMatch(readme, /npm start/u);
  assert.match(selfCheck, /P7-3\.png/u);
});


test('legacy stub consolidation keeps at most twelve deployable functions and queries cannot select a feature', async () => {
  async function functionsAt(dir) {
    const files = [];
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) files.push(...await functionsAt(new URL(`${entry.name}/`, dir)));
      else if (/\.js$/u.test(entry.name)) files.push(entry.name);
    }
    return files;
  }
  assert.equal((await functionsAt(new URL('../api/', import.meta.url))).length, 12);
  const { default: handler } = await import('../api/[feature].js');
  for (const url of ['/api/unknown?feature=ai', '/api/device?feature=ai', '/api/ai/extra']) {
    let code, body;
    handler({url}, {setHeader() {}, status(value) { code=value; return {json(value) {body=value;}};}});
    assert.equal(code,404); assert.deepEqual(body,{error:'NOT_FOUND'});
  }
});
