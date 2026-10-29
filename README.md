# BYTE BACK 방어전 · 내 자료실 (R5 기반)

## 진행 중: 3단계 제작 1 — 로그인·로그아웃 화면

2단계는 포털에서 통과했습니다. 현재는 3단계의 첫 제작으로 이메일·비밀번호 로그인과 로그아웃 화면만 추가했습니다. 공식 `@supabase/supabase-js` 2.117.2 SDK의 브라우저 배포본을 빌드 때 `public/vendor/supabase.js`로 복사하며, 외부 CDN에서 런타임 코드를 가져오지 않습니다. 로그인은 `signInWithPassword`, 현재 세션 로그아웃은 `signOut({ scope: 'local' })`, 화면 갱신은 동기 `onAuthStateChange` 콜백으로 처리합니다. 브라우저에는 공개 Project URL과 publishable key만 포함합니다. 비밀번호를 따로 저장하거나 JWT를 직접 만들지 않습니다. SDK의 세션 저장소는 이 탭의 `sessionStorage`이며, SDK가 세션 저장·삭제를 관리합니다.

**제작 1에서 서버 API는 아직 2단계의 공개 조회 상태입니다.** 로그인 화면이 생겼다고 메모가 보호된 것은 아닙니다. 비로그인 API 차단은 다음 제작 2에서 기존 `src/verify-login.mjs` 도우미를 그대로 사용해 구현하고, 추가·수정·삭제는 제작 3에서 구현합니다. 따라서 `aleph.config.json`과 `/aleph.json`의 단계는 아직 2로 유지합니다. 3단계를 완료하거나 제출할 수 있다고 표시하지 않습니다. 기존 가상 메모와 DB는 변경하지 않았습니다.

사용자는 Supabase Authentication → Users에서 연습 계정 A를 직접 생성했습니다. 비밀번호는 사용자가 관리하며 코드·문서·Git에 포함하지 않습니다. 현재 화면에서 로그인 전에는 이메일·비밀번호 입력과 로그인 버튼이 보이고, 성공 후에는 로그인 계정과 로그아웃 버튼이 보입니다. 실패 시 계정 정보 오류·이메일 미확인·요청 제한·연결 실패 등을 화면의 이유로 안내합니다. 로그아웃 요청 실패를 성공으로 표시하지 않습니다. 자동 시험은 SDK와 모의 Auth 응답을 사용하며 실제 계정 로그인 완료 증거가 아닙니다.

제작 1 확인 순서: 새 시크릿 창에서 첫 화면을 열고 A 계정으로 로그인 → 로그인 상태 표시와 로그아웃 버튼 확인 → 로그아웃 후 입력 화면 복귀 확인 → 틀린 비밀번호로 로그인 시 실패 이유 확인. 성공한 실제 계정 확인은 사용자가 실행한 뒤 기록합니다. `npm test`로 자동 시험을 실행하고, 로컬 빌드는 먼저 `npm ci` 후 `npm run build -- --local`을 사용합니다.

---

현재 구현은 **2단계: 자료를 코드 밖으로 옮깁니다**입니다. 1단계의 공개 자료실에서 시작했고, 같은 저장소·Vercel 프로젝트를 계속 사용합니다. 1단계 시작 커밋은 `0fc799e0b8c9432850ba0d135aed255b3b3fdaa0`입니다. 이 문서와 서버 조회 변경을 함께 담은 「2단계 저장점」 커밋을 제출 기준으로 사용합니다. 실제 SHA는 `git log -1 --oneline`과 배포의 `/aleph.json`으로 대조합니다.

- 공개 주소: https://choi-bujang-secret-vault-rho-six.vercel.app/
- 저장소: https://github.com/ChoiMgHub/choi-bujang-secret-vault
- 설정의 단계: `aleph.config.json` → `step: 2`

## 현재 동작과 남은 약점

브라우저는 `GET /api/notes`를 호출하고, Vercel 서버 함수가 Supabase `public.vault_notes`에서 가상 메모 네 건을 읽습니다. 화면은 `textContent`로 제목과 본문을 표시합니다. 서버는 고정된 테이블·조회 열·정렬만 사용하고 브라우저의 키·소유자·테이블 이름을 사용하지 않습니다. 비밀키는 브라우저 파일, API 응답, 로그에 넣지 않습니다. 조회 응답은 `no-store`, 다른 HTTP 메서드는 405입니다.

**아직 사용자 인증을 구현하지 않았으므로 누구나 `/api/notes`에서 가상 메모를 읽을 수 있습니다.** DB의 직접 읽기 권한을 막은 것과 서버 API 접근을 막은 것은 다릅니다. 3단계 전까지 실제 개인정보를 넣지 않습니다. `identityProvider`, `allowedRoutes`, `originalApiUrl`, `restoreRoute`는 후속 단계용으로 남겨 두었습니다. 판정기·탐지기 및 AI·침해 정보 API 뼈대는 아직 구현 완료가 아닙니다.

**과거 노출은 없어지지 않았습니다.** 최신 파일에서 제거했어도 1단계의 과거 공개 커밋과 옛 Vercel 배포에 메모가 남을 수 있습니다. Git 이력이나 이전 배포를 삭제하지 않았습니다. 실제 비밀값이 노출됐을 때는 키 폐기·교체와 이력·캐시·배포 정리가 별도로 필요합니다.

## DB 준비 (비공개 실행 파일)

가상 메모를 넣는 실행용 SQL 한 파일은 Supabase SQL Editor에서 직접 실행했습니다. 원문이 포함된 `step02_private_setup.sql`은 공개 저장소에 올리지 않습니다. 새 DB를 재현할 때도 같은 비공개 실행 파일을 SQL Editor에서 사용합니다. 이 저장소에서 원문을 다시 만드는 공개 시드나 자동 초기화는 제공하지 않습니다.

테이블은 `id uuid`, `owner_id uuid`(NULL 허용, `auth.users` 외래키 없음), `title text`, `content text`, `created_at timestamptz`로 구성합니다. RLS를 켜고 PUBLIC·anon·authenticated의 테이블 권한을 회수했습니다. 서버 역할에는 SELECT를 부여했습니다. SQL 실행 결과 화면에서 메모 4건, RLS true, owner_id 형식 uuid, anon/authenticated SELECT false, server SELECT true를 확인했습니다. 이 값은 DB 권한 확인이며 실제 API 인증 구현 증거는 아닙니다.

## Vercel 설정과 재현

프로젝트 Settings → Environment Variables에서 Production에 아래 두 항목을 저장합니다. 값은 코드나 채팅에 넣지 않습니다.

| 이름 | 형식·용도 | Vercel 유형 |
|---|---|---|
| `SUPABASE_URL` | Supabase Project URL, 서버의 DB 접속 주소 | Config |
| `SUPABASE_SECRET_KEY` | Supabase Settings → API Keys의 서버 전용 Secret key | Secret |

Node.js 22 이상을 사용합니다. 현재 사용 환경은 Node.js 24입니다. `npm ci` 후 `npm test`로 자동 시험을 실행합니다. `npm run build -- --local`은 DB 연결 없이 정적 빌드만 점검하며, 배포 식별 파일을 만들지 않습니다. 운영 `npm run build`는 Vercel 시스템 환경변수로 Git 저장소·커밋·배포 URL을 검증한 뒤 `/aleph.json`을 생성합니다. 시스템 환경변수가 없는 일반 로컬 실행을 실제 배포라고 표시하지 않습니다.

2단계부터 빌드는 `public/data.json`을 생성하지 않고, 이전 빌드 잔여 파일도 제거합니다. 루트 `data.json`은 원문 없는 빈 목록입니다. `vercel.json`은 첫 화면과 응답에 `X-Content-Type-Options: nosniff`를 설정합니다. GitHub main 변경은 연결된 Vercel 프로젝트에서 자동 배포됩니다. 환경변수 변경은 새 배포에 반영됩니다.

## 최신 소스와 정적 결과물 검색

PowerShell에서 저장소 폴더를 연 다음 아래 명령을 실행합니다. 패턴은 원문 전체를 문서에 다시 싣지 않고 기존 시드 문장 형식을 검색합니다. 결과가 없어야 하며, `git grep`의 종료 코드 1은 일치 항목 없음입니다.

```powershell
git grep -n -E '실습용[[:space:]]+가상[[:space:]]+.{1,30}[[:space:]]+기록' -- .
Get-ChildItem .\public -File -Recurse | Select-String -Pattern '실습용\s+가상\s+.{1,30}\s+기록'
```

코드·정적 파일에는 실제 서버 키가 없어야 합니다. 키의 환경변수 **이름**이 서버 소스에 있는 것은 값 유출과 다릅니다. `.env*`, `.private/`, 시드 SQL과 제출 산출물은 Git에서 제외합니다. 현재 파일 검색은 과거 커밋·옛 배포를 정리했다는 증거가 아닙니다.

## 배포 후 직접 확인

새 시크릿 창에서 다음 결과를 확인합니다.

1. `/` → 가상 메모 네 카드가 보임. HTML 소스에는 메모 원문이 없고 서버 API에서 가져옴.
2. `/data.json` → 404. 빈 목록을 반환하는 구현도 과제 기준상 허용되지만 현재 구현은 파일 제거 방식임.
3. `/aleph.json` → step 2, 본인 저장소, 실제 배포 커밋이 보임. 배포 URL은 Vercel이 부여한 개별 배포 주소일 수 있음.
4. `/api/notes` → 비로그인 상태에서도 네 건 조회됨. 이것은 의도적으로 기록하는 **남은 약점**임.
5. 첫 화면 응답 헤더 → `X-Content-Type-Options: nosniff`.
6. `/api/notes`에 POST → 405. 서버 설정이 빠졌으면 503, DB 조회 오류는 비밀값 없는 502.

`npm run verify:step2`는 위 운영 경로에 실제 비로그인 요청을 보내 결과를 `artifacts/step2-verification.json`으로 저장합니다. 로컬 HEAD와 배포 커밋도 대조합니다. 메모 본문·키를 저장하지 않으며 실패를 PASS로 바꾸지 않습니다. 자동 시험은 로컬 모의 DB 응답을 사용하며 실제 DB·배포·심판 결과와 구분합니다.

## 제출 묶음

배포 확인 후 커밋된 깨끗한 작업 폴더에서, Git에 올리지 않는 `bundle-notes.json`에 이번 변경 설명을 적습니다.

```json
{
  "explanation": "가상 메모를 DB로 옮기고 최신 공개 파일의 원문을 제거했습니다. 서버 전용 환경변수로 조회 API를 연결했습니다. API의 비로그인 조회와 옛 공개 이력의 한계는 남아 있습니다.",
  "blockedAt": null
}
```

그다음 `npm run bundle`을 실행합니다. 실제 배포의 6가지 점검과 저장소·제출 커밋 일치가 모두 통과해야 `artifacts/submission.json`을 만듭니다. `bundle-notes.json`과 `artifacts/`는 커밋하지 않습니다. 이 자기 점검과 JSON 생성은 **운영 심판의 통과 판정이 아닙니다.** 최종 판정은 방어전 포털에서 확인합니다.

## 되돌릴 때

먼저 `git status`, `git diff`로 이번 변경과 다른 작업을 확인합니다. 사라질 내용을 검토하고 확인한 뒤 이번 단계 파일만 복원합니다. DB 자료와 다른 작업을 보존하며 `reset --hard`는 사용하지 않습니다.
