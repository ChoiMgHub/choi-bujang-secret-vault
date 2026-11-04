import { copyFile, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const source = resolve(root, 'data.json');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (!Number.isInteger(config.step) || config.step < 1 || config.step > 12) {
  throw new Error('aleph.config.json의 단계는 1~12 정수여야 합니다.');
}
await mkdir(resolve(root, 'public'), { recursive: true });
if (config.step < 5) {
  await mkdir(resolve(root, 'public', 'vendor'), { recursive: true });
  await copyFile(resolve(root, 'node_modules/@supabase/supabase-js/dist/umd/supabase.js'),
    resolve(root, 'public/vendor/supabase.js'));
  await copyFile(resolve(root, 'node_modules/@supabase/supabase-js/LICENSE'),
    resolve(root, 'public/vendor/SUPABASE-LICENSE.txt'));
} else {
  // Auth now runs in the server function, including SDK session refresh.
  await rm(resolve(root, 'public', 'vendor'), { recursive: true, force: true });
  const forbidden = /sb_publishable_[A-Za-z0-9_-]{8,}|sb_secret_[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/u;
  async function scan(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) await scan(path);
      else if (/\.(?:html|js|json|map|css)$/u.test(entry.name)
          && forbidden.test(await readFile(path, 'utf8'))) {
        throw new Error('브라우저 배포 파일에 키 또는 토큰 모양의 값이 있습니다.');
      }
    }
  }
  await scan(resolve(root, 'public'));
}
if (config.step === 1) {
  const data = JSON.parse(await readFile(source, 'utf8'));
  if (!Array.isArray(data.notes)) throw new Error('실습용 공개 자료 형식을 확인하세요.');
  await copyFile(source, output);
} else {
  // Remove an old build/cache artifact too; merely skipping the copy is insufficient.
  await rm(output, { force: true });
  console.log('공개 data.json을 제거했습니다. 자료는 서버 API에서만 읽습니다.');
}
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
} else {
  await rm(resolve(root, 'public', 'aleph.json'), { force: true });
}
