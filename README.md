# BYTE BACK 방어전 · 내 자료실 (R5 기반)

현재 **4단계: 로그인해도 내 자료만 보이게 합니다**의 제작 3 SQL을 준비했습니다. 사용자가 제작 1 SQL 실행 뒤 A 소유 4건·B 소유 1건을 확인했고, 제작 2 배포 후 새 Chrome 시크릿 창에서 A·B 각각 로그인·자기 가상 메모 확인·새 메모 추가·수정·삭제·새로고침 후 삭제 유지를 모두 정상이라고 확인했습니다. API는 검증된 사용자 ID를 기준으로 메모 소유자를 검사합니다. **제작 3 SQL의 실제 Supabase 적용과 적용 후 확인·제출은 아직 남아 있습니다.**

이전 3단계에서 사용자는 실제 로그인·잘못된 비밀번호 거부·비로그인 자료 차단·정상 A 조회·로그아웃 후 메모 제거·메모 추가·수정·삭제를 확인했습니다. 3단계 자동 시험은 당시 28개를 통과했습니다. 사용자는 3단계를 마쳤다고 알리고 4단계 안내를 제공했으며, 이 README는 별도의 포털 점수나 심판 결과를 추정해 기록하지 않습니다.

- 공개 주소: https://choi-bujang-secret-vault-rho-six.vercel.app/
- 저장소: https://github.com/ChoiMgHub/choi-bujang-secret-vault
- 설정: `aleph.config.json`의 `step: 4`, 실제 구현한 목록·단건 CRUD 경로 5개
- 1단계 시작 커밋: `0fc799e0b8c9432850ba0d135aed255b3b3fdaa0`
- 2단계 통과 저장점: `9a1b535a3bd4c3733ebfff4e2e094858438be3f6`
- 제작 1 커밋: `05fbd16d0e3ed3c3ab210d031dd2f5d7d9470489`

## 제작 1: 공식 SDK 로그인·로그아웃

공식 `@supabase/supabase-js` 2.117.2 브라우저 SDK를 빌드 때 `public/vendor/supabase.js`로 복사합니다. 외부 CDN에서 런타임 코드를 가져오지 않습니다. 이메일·비밀번호 로그인은 `signInWithPassword`, 현재 세션 로그아웃은 `signOut({ scope: 'local' })`, 화면 갱신은 동기 `onAuthStateChange` 콜백으로 처리합니다. 비밀번호나 JWT를 직접 만들거나 저장하지 않습니다. 공개 Project URL과 publishable key만 브라우저에 포함하고, SDK가 이 탭의 sessionStorage에서 세션을 관리합니다. 로그인 실패는 계정 정보 오류·이메일 미확인·요청 제한·연결 실패 등의 이유를 표시하며 비밀번호 입력은 지웁니다.

사용자는 Supabase Authentication → Users에서 연습 계정 A를 직접 생성하고 실제 로그인 성공과 잘못된 비밀번호 거부를 확인했습니다. 제작 2 배포 후 정상 A 조회와 로그아웃 뒤 메모 제거도 확인했습니다. 실제 비밀번호는 사용자가 보관하고 코드·문서·Git에 포함하지 않습니다.

## 제작 2: 자료 API에서 토큰 확인

`api/notes.js`가 시작 틀의 **`src/verify-login.mjs`를 수정 없이 그대로 import**합니다. `createLoginVerifier`를 서버 런타임에 한 번 생성하고 요청의 Authorization Bearer를 검사합니다. 브라우저의 userId·role·소유자 헤더나 쿼리를 인증 근거로 사용하지 않습니다. 도우미는 Supabase 학생 토큰과 운영 심판 토큰의 발급자 경로를 구분해 검증합니다. Supabase SDK의 getClaims가 서명과 만료를 확인한 뒤 발급자·대상·역할·사용자 ID를 확인하며, 심판 토큰은 시작 틀에 정해진 서명·클레임 검사를 유지합니다. judgeIssuer는 변경하지 않았습니다.

`identityProvider`에는 공개 정보만 기록했습니다.

| 항목 | 값 |
|---|---|
| issuer | https://prplojzcswmpaqhcnmwl.supabase.co/auth/v1 |
| audience | authenticated |
| jwksUrl | https://prplojzcswmpaqhcnmwl.supabase.co/auth/v1/.well-known/jwks.json |

메모 GET은 토큰이 없거나 검증이 실패하면 **401 JSON `{ "error": "AUTH_REQUIRED" }`**로 응답하며 DB의 메모를 읽지 않습니다. 통과한 요청만 서버 전용 키로 고정된 테이블·조회 열을 읽습니다. 서버 설정 오류는 비밀값 없는 503, DB 조회 오류는 비밀값 없는 502를 반환합니다. 응답은 no-store이며 X-Content-Type-Options: nosniff를 유지합니다.

브라우저는 로그인 전 메모를 요청하지 않습니다. 로그인 세션의 토큰을 Authorization 헤더에 붙여 서버에 요청하고, 화면은 제목·본문을 textContent로 표시합니다. 로그아웃·계정 변경 시 기존 메모를 지우고 진행 중 요청을 취소합니다. 취소를 무시한 늦은 응답도 화면 버전 검사로 차단해 로그아웃 뒤 메모가 다시 나타나지 않도록 합니다. 토큰과 비밀번호를 화면·로그에 출력하지 않습니다.

로그아웃 후 브라우저는 토큰 없이 요청하므로 401이 됩니다. 단, JWT 자체는 만료 전까지 유효할 수 있으므로 이 구현을 이미 복사된 접근 토큰의 즉시 폐기라고 주장하지 않습니다. 토큰 즉시 폐기 기능은 이번 제작 범위가 아닙니다.

## 제작 3: 로그인한 계정의 메모 추가·조회·수정·삭제

브라우저의 내 가상 메모 양식과 카드의 수정·삭제 버튼을 연결했습니다. 수정 버튼은 단건 GET으로 최신 내용을 읽어 양식에 채우고 PUT으로 저장합니다. 삭제는 확인 후 DELETE로 처리하고 목록을 다시 조회합니다. 로그인 토큰은 SDK 세션에서 가져와 Authorization 헤더로 보내며 사용자 ID·소유자 ID를 브라우저에서 결정하지 않습니다. 저장 실패 시 초안을 보존하고, 로그아웃 시 메모와 초안을 지웁니다. 제목·본문은 textContent로 표시합니다.

| 실제 경로 | 요청·응답 계약 |
|---|---|
| GET /api/notes | 서버가 확인한 사용자 소유의 메모 배열 `[{id,title,body}]` |
| POST /api/notes | `{id?,title,body}` 입력. id는 UUID이며 생략하면 서버가 생성. 성공은 201과 `{id}` |
| GET /api/notes/:id | 단건 `{id,title,body}`. 없거나 삭제된 메모는 404 |
| PUT /api/notes/:id | `{title,body}`로 수정. 선택 id가 있으면 경로와 같아야 함. 성공은 단건 객체, 없으면 404 |
| DELETE /api/notes/:id | 성공은 `{id}`, 이후 같은 ID의 GET은 404 |

DB의 기존 content 열을 API의 body 필드에 대응시킵니다. 추가할 때 owner_id는 검증된 identity.userId로만 저장합니다. 클라이언트의 owner_id·userId·role은 소유자 지정에 사용하지 않고, 수정에서도 owner_id를 바꾸지 않습니다. POST는 insert이므로 같은 ID가 있으면 409이고 기존 자료를 덮어쓰지 않습니다. 잘못된 입력·UUID는 400, 큰 JSON은 413, 잘못된 인증은 자료 없이 401, DB 오류는 비밀값 없는 502입니다. 제목은 공백만으로 만들 수 없고 최대 200자, 본문은 최대 10,000자입니다.

3단계 당시 원래 네 메모는 owner_id가 NULL이었고 첫 로그인 계정에 자동 배정하지 않았습니다. 4단계 제작 1에서 사용자가 SQL을 직접 실행해 원래 네 건을 현재 A 계정에 연결하고 B의 가상 시험 메모 한 건을 추가했습니다. 메모 원문이 포함된 실행용 SQL은 공개 Git에 추가하지 않습니다.

3단계에서 사용자가 Supabase SQL Editor에서 서버 역할의 SELECT·INSERT·UPDATE·DELETE가 모두 true, RLS가 true, anon·authenticated의 SELECT가 false인 것을 확인했습니다. 같은 권한 설정은 `sql/step03-crud-permissions.sql`에 원문이나 비밀값 없이 보관했습니다. 제작 2까지는 이 DB 권한을 변경하지 않습니다. 4단계 제작 3에서 authenticated의 최소 권한과 본인 행 RLS 정책을 별도로 검토·적용해야 합니다.

## 4단계 제작 2: 메모 API 소유자 검사

3단계의 단건 GET·PUT·DELETE에는 소유자 비교가 없었습니다. 변경 전 로컬 모의 DB 시험에서 B가 A의 ID를 지정해 읽기·수정·삭제할 수 있음을 다시 확인했습니다. 이는 실제 배포의 B 계정으로 수행한 시험이 아닙니다.

이제 목록과 단건 GET 모두 DB 조회에 `owner_id = identity.userId`를 넣습니다. PUT·DELETE도 ID와 검증된 소유자 ID를 같은 DB 문장의 조건으로 사용합니다. 변경 직전에 소유자가 달라져도 그 행은 수정·삭제 대상이 되지 않습니다. 다른 사람의 ID와 없는 ID는 모두 자료 없는 404 JSON `{ "error": "NOT_FOUND" }`로 응답합니다.

POST는 서버가 검증한 ID를 owner_id로 저장하며 클라이언트가 보낸 owner_id·userId·role을 소유자 지정에 사용하지 않습니다. PUT의 정상 본문은 `{title,body}`이고 owner_id 필드를 넣은 소유자 변경 요청은 400 JSON으로 거부합니다. 수정할 기존 행은 소유자 조건으로 제한하고 수정 후 소유자도 검증된 ID로 고정합니다. URL·헤더·본문의 사용자 주장은 권한 근거가 아닙니다.

내부 조회의 owner_id는 서버에서 확인한 뒤 제거하므로 단건 응답은 계속 `{id,title,body}`입니다. 목록도 같은 객체의 배열이고 삭제 응답은 `{id}`입니다. 예상과 달리 다른 계정의 행이 DB 응답에 섞여도 메모를 반환하지 않고 502 JSON 오류로 중단합니다. 서버 비밀키는 RLS를 우회할 수 있으므로 API 소유자 검사를 DB 정책으로 대체하지 않습니다.

자동 시험은 임시 서명 키·모의 Auth/DB를 사용해 A/B 각각의 정상 CRUD, 양방향 타인 및 소유자 미지정 메모 접근 거부, 소유자 변경 거부, 쓰기 직전 소유자 변경, 잘못된 DB 응답의 자료 차단을 확인합니다. 실제 DB의 RLS 동작이나 실제 A/B 배포 시험을 수행한 증거로 해석하지 않습니다.

이번 제작 2의 검증 환경에서 `npm test` 32개와 `npm run build -- --local`이 통과했습니다. 과거 3단계 점검 테스트는 현재 설정이 4단계로 바뀌어도 3단계 조건을 검증하도록 명시했습니다. 사용자 PC에서 이 명령을 실행했다고 기록하지 않습니다.

제작 2 배포 후 사용자는 먼저 로그아웃하고 현재 A 계정으로 새로 로그인합니다. 기존 네 카드가 보이는지 확인하고, 별도의 새 가상 연습 메모를 추가·수정·삭제합니다. A에서 로그아웃한 후 B로 로그인해 B의 한 카드만 보이는지 확인하고 같은 연습을 합니다. 원래 네 메모와 B의 고정 시험 메모는 삭제하지 않고 보존합니다. 목록 분리만으로 단건 API의 타인 접근 거부까지 확인됐다고 기록하지 않습니다.

사용자는 위 과정을 A·B 두 계정에서 모두 수행했고, 새로고침 후 삭제 유지까지 문제가 없다고 알려주었습니다. 이는 실제 배포에서의 정상 계정 사용과 목록 분리 확인입니다. 실제 계정 토큰으로 타인 ID를 지정한 단건 API 시험이나 직접 Data API의 authenticated 접근을 실행했다고 기록하지 않습니다.

## 4단계 제작 3: DB 최소 권한과 본인 행 RLS (적용 대기)

`sql/step04-owner-rls.sql`은 사용자가 기존 Supabase SQL Editor에서 검토하고 실행할 SQL입니다. `information_schema.role_table_grants`와 `has_table_privilege`로 적용 전후를 확인합니다. PUBLIC·anon·authenticated의 테이블 권한을 먼저 회수하고 authenticated에 SELECT·INSERT·UPDATE·DELETE만 부여합니다. SELECT·DELETE에는 기존 행 USING, INSERT에는 새 행 WITH CHECK, UPDATE에는 기존 행 USING과 새 행 WITH CHECK로 `(SELECT auth.uid()) = owner_id`를 적용합니다. 서버 역할의 기존 네 권한은 보존합니다. 메모 내용·소유자·계정·다른 테이블은 변경하지 않습니다.

기존 정책 중 이 단계에서 관리하는 네 정책 외의 것이 있거나 예상 밖의 상속 권한이 남으면 오류로 중단하고 트랜잭션을 되돌립니다. 기존 네 정책은 같은 정의로 다시 만들므로 반복 실행이 가능합니다. 마지막 결과는 anon의 네 권한이 false, authenticated의 네 권한이 true, 추가 권한 false, RLS true, 정책 수 4여야 합니다. 권한의 true는 모든 행 접근 허용을 뜻하지 않고 RLS가 본인 행으로 제한합니다.

AI의 별도 PGlite 0.5.13 PostgreSQL WASM 시험 환경에서 실제 SQL을 적용하고 반복 실행했습니다. 익명 CRUD 거부, A/B 각자 CRUD 허용, 타인 읽기·수정·삭제의 0행 결과, 타인/null 소유자 추가와 소유자 변경 거부, 기존 행 보존, 예상 밖의 정책·상속 권한에서 변경 중단을 확인했습니다. 시험의 auth.uid()는 로컬 요청 주체를 읽는 대역이며 실제 Supabase Auth나 사용자 DB를 시험한 결과가 아닙니다. 프로젝트의 런타임 의존성에는 시험 엔진을 추가하지 않았습니다.

적용 뒤 A/B의 정상 화면 사용을 다시 확인합니다. 현재 서버 비밀키 경로는 RLS를 우회할 수 있으므로 앱 정상 동작만으로 authenticated의 직접 Data API RLS까지 검증했다고 주장하지 않습니다. 심판이 점수에 반영하는 직접 Data API 확인은 안내문대로 익명 공개 키 요청이며, 실제 확인 전에는 완료로 기록하지 않습니다.

## 배포·재현

같은 Supabase DB와 Vercel 프로젝트를 계속 사용합니다. 배포·빌드가 기존 메모를 초기화하거나 계정 소유자로 재배정하지 않습니다. 실제 사용자가 추가·수정·삭제를 누르면 해당 작업이 DB에 반영됩니다. Production 환경변수는 기존 두 개를 유지합니다.

| 이름 | 용도 | Vercel 유형 |
|---|---|---|
| SUPABASE_URL | 위 Supabase 프로젝트의 주소 | Config |
| SUPABASE_SECRET_KEY | 서버 전용 Secret key | Secret |

Node.js 22 이상(현재 사용 환경 24)에서 npm ci 후 npm test로 자동 시험을 실행합니다. npm run build -- --local은 로컬 정적 빌드이고 배포 식별 파일을 만들지 않습니다. 운영 빌드는 Vercel의 저장소·커밋·배포 URL 시스템 환경변수를 검증해 `/aleph.json`을 생성합니다. GitHub main의 변경은 기존 Vercel 프로젝트에 자동 배포됩니다. 환경변수 변경은 새 배포에 반영됩니다.

## 이전 3단계 제작 3 배포 후 사용자 확인

사용자가 안내한 순서로 실제 배포를 시험한 뒤 로그인과 메모 추가·수정·삭제가 모두 정상이라고 알려주었습니다. 아래는 재현 순서입니다. 자동 시험 결과와 사용자 확인은 구분하며, 비밀번호나 토큰은 전달받지 않았습니다.

1. 새 시크릿 창의 첫 화면 → 로그인 양식만 보이고 메모 양식·목록은 숨김. 익명 `/api/notes`는 401 JSON 오류.
2. A 로그인 → 내 가상 메모 양식과 A의 목록. 처음에는 빈 목록일 수 있음.
3. 새 가상 메모 추가 → 카드 표시 → 새로고침 후 유지.
4. 카드의 수정 → 제목·내용 변경 → 수정 저장 → 새로고침 후 변경 유지.
5. 카드 삭제 확인 → 목록에서 사라짐 → 새로고침 후에도 없음. API 시험에서는 삭제한 ID의 GET이 404인지도 확인.
6. 로그아웃 → 메모 양식·목록·초안 제거. 새로고침 후에도 숨김.

자동 시험은 임시 서명 키·모의 Auth/DB 응답을 사용합니다. 실제 사용자 비밀번호나 토큰을 받은 것으로 기록하지 않습니다. 시험은 서명 검증·익명/위조 거부·검증된 ID의 소유자 저장·계정별 목록·UUID 생성과 중복 거부·CRUD 형식·삭제 후 404·입력 검증·소유자 검사·SDK 로그인·화면 CRUD·로그아웃 후 늦은 응답 차단을 확인합니다.

## 이전 3단계의 제출 자기 점검과 묶음

`npm run verify:step3`는 3단계 당시의 배포에 익명·잘못된 토큰 요청을 보내 목록/단건/쓰기 거부와 배포 정보를 검사합니다. 임의의 사용하지 않은 UUID를 사용하고 쓰기 본문이나 로그인 자격 증명을 보내지 않습니다. 결과는 `artifacts/step3-verification.json`에 상태와 판정만 저장합니다. **이 점검은 실제 A 계정의 CRUD를 자동 확인한 증거가 아닙니다.** A의 브라우저 작업과 포털 심판 판정은 별도로 확인합니다.

위 명령은 step 3 배포를 전제로 한 과거 단계용입니다. 4단계 제출 자기 점검과 묶음은 제작 3 적용 및 실제 배포 확인 뒤 별도로 갱신합니다. 현재 제작 2만으로 4단계 제출 준비가 끝났다고 기록하지 않습니다. 3단계에서는 실제 A의 CRUD 확인 후 Git에 올리지 않는 bundle-notes.json에 수행 내용과 남은 허점을 적고 `npm run bundle`을 실행했습니다. 깨끗한 작업 폴더의 현재 커밋과 배포 커밋이 일치하고 실제 HTTP 자기 점검이 통과해야 `artifacts/submission.json`이 만들어집니다. 본문·비밀번호·토큰·서버 비밀키는 묶음에 포함하지 않습니다. 자기 점검 통과와 파일 생성이 포털 심판 통과를 뜻하지는 않습니다.

## 2단계에서 보존한 결과와 과거 이력의 한계

2단계에서 메모 네 건을 Supabase `public.vault_notes`로 옮겼습니다. id uuid, owner_id uuid(NULL 허용·auth.users 외래키 없음), title text, content text, created_at timestamptz로 구성했습니다. RLS를 켜고 PUBLIC·anon·authenticated의 테이블 권한을 회수했으며 서버 역할에는 SELECT를 부여했습니다. 사용자가 SQL Editor 실행 결과에서 메모 4건, RLS true, owner_id uuid, 일반 역할 SELECT false, 서버 SELECT true를 확인했습니다. 시드 실행용 SQL은 원문이 있어 공개 Git에 올리지 않았습니다.

최신 루트 data.json은 빈 목록이고 public/data.json은 빌드 때 잔여 파일까지 제거합니다. 2단계의 익명 조회 자기 점검 `npm run verify:step2`는 당시 동작을 확인하는 과거 단계용이며, 3단계 인증 적용 뒤에는 같은 공개 조회 결과를 기대하면 안 됩니다.

최신 소스의 원문 제거가 과거 노출까지 지웠다는 뜻은 아닙니다. 1단계 공개 커밋과 옛 배포에는 메모가 남을 수 있고, 이력을 삭제하거나 다시 작성하지 않았습니다. 실제 키가 노출된 경우에는 폐기·교체와 과거 이력·배포 정리가 별도로 필요합니다.

PowerShell에서 최신 소스와 정적 결과물의 기존 시드 문장 형식을 확인합니다. 일치 결과가 없어야 하며 git grep 종료 코드 1은 일치 항목 없음입니다.

```powershell
git grep -n -E '실습용[[:space:]]+가상[[:space:]]+.{1,30}[[:space:]]+기록' -- .
Get-ChildItem .\public -File -Recurse | Select-String -Pattern '실습용\s+가상\s+.{1,30}\s+기록'
```

`.env*`, `.private/`, 비공개 시드 SQL, bundle-notes.json, artifacts/는 커밋하지 않습니다. 서버 소스에 환경변수 이름이 있는 것은 실제 키 값의 노출과 다릅니다. 판정기·탐지기와 AI/침해 정보 API의 미구현 뼈대는 아직 완성된 기능이라고 표시하지 않습니다.

## 되돌릴 때

git status와 git diff로 이번 변경과 다른 작업을 구분하고, 사라질 내용을 먼저 확인합니다. 확인 후 이번 단계 파일만 복원하고 DB와 다른 작업을 보존합니다. reset --hard는 사용하지 않습니다.
