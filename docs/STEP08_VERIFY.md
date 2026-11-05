# 8단계 DB 준비와 실제 확인

2026-11-05 사용자가 기존 Supabase에 SQL을 적용하고 권한 결과 9행을 제공했다. 모두 예상과 일치했다. 아래 DB 절차는 재현 기록이며 다시 실행할 필요는 없다. 최종 배포 뒤 실제 로그인 계정으로 API를 확인한다.

## 사용자가 완료한 DB 적용 순서

1. 같은 브랜치의 `sql/step08-resource-zones.sql`을 열고 전체 내용을 복사한다.
2. 기존 자료실이 사용하는 Supabase 프로젝트의 SQL Editor에서 새 쿼리를 연다. 새 프로젝트를 만들지 않는다.
3. SQL 전체를 붙여 넣고 Run을 누른다.
4. 마지막 권한 결과 9행을 확인한다. 이 결과 표는 이번 포트폴리오의 의미 있는 화면 근거이므로 표 전체가 보이도록 캡처한다.
5. 결과 표 또는 첫 오류를 전달한다. 오류가 있으면 다른 SQL로 우회하거나 강사 권한을 임의로 추가하지 않는다.

| 대상 역할 | 대상 표 | can_read | can_create / can_update / can_delete | rls_enabled |
|---|---|---|---|---|
| anon / authenticated | 세 표 모두 | false | 모두 false | true |
| service_role | vault_notices | true | 모두 true | true |
| service_role | vault_instructor_materials / vault_resource_roles | true | 모두 false | true |

이 SQL은 기존 메모·계정·비밀번호를 변경하지 않는다. 공개 실습용 공지 한 건만 추가하며 강사 역할을 부여하지 않는다. SQL 시험 환경에서 통과한 결과와 실제 Supabase 결과는 별도로 기록한다.

## DB 적용 확인 뒤 진행할 일

AI가 최종 저장점·배포 정보 대조·실제 HTTP 점검·제출 묶음을 진행한다. 사용자는 최종 배포된 자료실에서 A·B 각각 자신의 메모 읽기와 상대 메모 거부를 다시 확인하고, 로그인 상태의 공지 읽기·공지 쓰기 거부·강사 자료 및 관리 API 거부를 확인한다. 구체적인 클릭과 요청 순서는 배포 뒤 안내한다.

기존 A·B 캡처는 변경 전 단건 조회 근거다. 강사의 정상 관리 동작은 모의 API 시험에서만 확인했으며 실제 강사 계정을 만들거나 권한을 부여한 사실은 없다. 터미널 출력 캡처는 필요하지 않다.

## 배포 후 A·B 계정의 실제 API 확인

기존 자료실 주소에서 로그인한 뒤 F12로 개발자 도구를 열고 Console 탭에서 아래 코드를 한 번 실행한다. 현재 사이트의 로그인 쿠키를 브라우저가 자동으로 사용하며 토큰을 읽거나 출력하지 않는다. 공개 공지 한 건을 읽고, 허용되지 않는 쓰기·강사 자료·관리 요청이 거부되는지 확인한다. 본문에 실제 자료를 넣지 않으므로 새 메모나 공지를 만들지 않는다.

```js
(async () => {
  const checks = [
    ['공지 읽기', 'GET', '/api/notices/80000000-0000-4000-8000-000000000001', 200],
    ['공지 쓰기', 'POST', '/api/notices', 403],
    ['강사 자료', 'GET', '/api/instructor/80000000-0000-4000-8000-000000000002', 403],
    ['강사 관리', 'POST', '/api/admin/notices', 403]
  ];
  const rows = [];
  for (const [항목, method, path, 예상] of checks) {
    const response = await fetch(path, { method, credentials: 'same-origin', cache: 'no-store',
      headers: { 'X-Requested-With': 'vault-ui', 'X-Role': 'instructor',
        ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) },
      ...(method === 'POST' ? { body: JSON.stringify({ role: 'instructor' }) } : {}) });
    const data = await response.json().catch(() => ({}));
    rows.push({ 항목, 예상, 실제: response.status, 사유: data.error || '', 통과: response.status === 예상 });
  }
  console.table(rows);
})();
```

예상 결과는 공지 읽기 200, 공지 쓰기 403 NOTICE_READ_ONLY, 강사 자료·강사 관리 각각 403 INSTRUCTOR_REQUIRED다. 일부러 넣은 클라이언트 역할이 강사 권한으로 승격되지 않아야 한다. 401이면 로그인 상태부터 확인하고, 다른 상태나 사유면 실제 결과를 그대로 전달한다. 출력은 텍스트로 전달해도 된다.

A에서 위 확인과 기존 ‘상대 메모 조회 차단 확인’을 수행하고 로그아웃한 뒤 B에서도 반복한다. 자기 메모 200 / 상대 메모 404가 유지되어야 한다. 이 과정은 기존 시험 메모가 있어야 하며, 없는 시험 메모를 성공으로 처리하지 않는다. 최종 화면 캡처는 같은 내용을 반복하지 않고 권한 경계를 보여 줄 때만 사용한다.
