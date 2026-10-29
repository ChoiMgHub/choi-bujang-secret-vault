# BYTE BACK 방어전 · 내 자료실 (R5 기반)

현재 **3단계 제작 2: 서버에서 로그인 토큰 확인**까지 구현 중입니다. 2단계는 포털에서 통과했고, 3단계 제작 1 배포 후 사용자가 A 계정의 정상 로그인과 잘못된 비밀번호 거부를 확인했습니다. 제작 2의 배포 후 A 메모 조회·로그아웃 확인은 아직 사용자 확인 전입니다. 메모 추가·수정·삭제를 붙이는 제작 3은 미구현이므로 **아직 3단계 완료·제출 상태가 아닙니다.**

- 공개 주소: https://choi-bujang-secret-vault-rho-six.vercel.app/
- 저장소: https://github.com/ChoiMgHub/choi-bujang-secret-vault
- 설정: `aleph.config.json`의 `step: 3`, 현재 구현 경로 `GET /api/notes`
- 1단계 시작 커밋: `0fc799e0b8c9432850ba0d135aed255b3b3fdaa0`
- 2단계 통과 저장점: `9a1b535a3bd4c3733ebfff4e2e094858438be3f6`
- 제작 1 커밋: `05fbd16d0e3ed3c3ab210d031dd2f5d7d9470489`

## 제작 1: 공식 SDK 로그인·로그아웃

공식 `@supabase/supabase-js` 2.117.2 브라우저 SDK를 빌드 때 `public/vendor/supabase.js`로 복사합니다. 외부 CDN에서 런타임 코드를 가져오지 않습니다. 이메일·비밀번호 로그인은 `signInWithPassword`, 현재 세션 로그아웃은 `signOut({ scope: 'local' })`, 화면 갱신은 동기 `onAuthStateChange` 콜백으로 처리합니다. 비밀번호나 JWT를 직접 만들거나 저장하지 않습니다. 공개 Project URL과 publishable key만 브라우저에 포함하고, SDK가 이 탭의 sessionStorage에서 세션을 관리합니다. 로그인 실패는 계정 정보 오류·이메일 미확인·요청 제한·연결 실패 등의 이유를 표시하며 비밀번호 입력은 지웁니다.

사용자는 Supabase Authentication → Users에서 연습 계정 A를 직접 생성하고 실제 로그인 성공과 잘못된 비밀번호 거부를 확인했습니다. 실제 비밀번호는 사용자가 보관하고 코드·문서·Git에 포함하지 않습니다.

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

## 현재 한계와 다음 제작

제작 2는 로그인 여부를 검사하는 단위입니다. 현재 정상 로그인한 계정에는 기존 가상 메모 네 건을 조회하는 2단계 동작을 유지하며 소유자별 목록 필터링은 아직 없습니다. 계정별 목록과 추가 시 owner_id 저장, 단건 GET·PUT·DELETE는 제작 3에서 구현하고, 타인의 단건 자료 접근을 막는 소유자 권한 검사는 4단계에서 구현합니다. 실제 개인정보를 넣지 않습니다.

현재 POST·PUT·DELETE는 미구현이라 405입니다. `allowedRoutes`에는 실제 구현한 GET 경로만 기록했습니다. 제작 3 전에는 npm run bundle로 3단계 제출 묶음을 만들지 않습니다. 전체 3단계 확인 뒤 저장점과 자기 점검을 갱신합니다.

## 배포·재현

같은 Supabase DB와 Vercel 프로젝트를 계속 사용하며 이번 제작은 DB 자료를 변경하지 않습니다. Production 환경변수는 기존 두 개를 유지합니다.

| 이름 | 용도 | Vercel 유형 |
|---|---|---|
| SUPABASE_URL | 위 Supabase 프로젝트의 주소 | Config |
| SUPABASE_SECRET_KEY | 서버 전용 Secret key | Secret |

Node.js 22 이상(현재 사용 환경 24)에서 npm ci 후 npm test로 자동 시험을 실행합니다. npm run build -- --local은 로컬 정적 빌드이고 배포 식별 파일을 만들지 않습니다. 운영 빌드는 Vercel의 저장소·커밋·배포 URL 시스템 환경변수를 검증해 `/aleph.json`을 생성합니다. GitHub main의 변경은 기존 Vercel 프로젝트에 자동 배포됩니다. 환경변수 변경은 새 배포에 반영됩니다.

## 제작 2 배포 후 사용자 확인

1. 새 시크릿 창에서 첫 화면 → 로그인 입력이 보이고 메모는 보이지 않아야 합니다.
2. 로그인 없이 `/api/notes` 직접 열기 → 401과 JSON 오류, 메모 없음.
3. 정상 A 로그인 → 기존 가상 메모 네 건 표시.
4. 로그아웃 → 로그인 입력 화면으로 복귀, 기존 메모 제거. 새로고침 후에도 메모 없음.
5. 틀린 비밀번호 → 실패 이유가 보이고 메모 없음.
6. `/data.json` → 404, `/aleph.json` → 현재 커밋과 step 3, 첫 화면 → nosniff 헤더 유지.

자동 시험은 임시 서명 키·모의 Auth/DB 응답을 사용합니다. 실제 사용자의 비밀번호·토큰으로 시험한 것으로 기록하지 않습니다. 시험은 실제 SDK를 통한 서명 검증, 정상 학생/심판 토큰, 위조·만료·다른 발급자·대상·역할 토큰 거부, 익명/사용자 위조 거부, 공개 파일 빌드, 로그인 상태 표시와 로그아웃 후 늦은 응답 차단을 확인합니다. 자기 점검과 배포 성공은 운영 심판의 최종 통과 판정이 아닙니다.

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
