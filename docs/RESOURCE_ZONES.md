# 8단계 자원 구분과 서버 검사

이 문서는 서버가 자료 종류를 구별하는 이름과 경로를 정한다. 구역 식별은 `src/resource-zones.mjs`, 판정기 허용 여부는 `src/resource-policy.mjs`, 최종 공지·강사 자료 검사는 `src/resource-api.mjs`가 담당한다. 기존 메모 소유자 검사는 `api/notes.js`가 유지한다.

| 자료 종류 | 서버 내부 구역 ID | 판정기 service | 실제 API 기본 경로 | 엔진 가상 요청의 기본 경로 |
|---|---|---|---|---|
| 학생 메모 | student_notes | notes | /api/notes | /notes |
| 반 공지 · 강사가 작성한 공지 | class_notices | notices | /api/notices | /notices |
| 강사 전용 자료 | instructor_materials | instructor | /api/instructor | /instructor |

자료 한 건은 `구역 ID:item:자료 ID`로 식별한다. 예를 들어 같은 자료 ID가 a여도 메모의 `student_notes:item:a`와 공지의 `class_notices:item:a`는 다른 자원이다. ID 없는 기본 경로는 `구역 ID:collection`으로 구별해 둔다. 전체 목록을 허용할지는 이 식별과 별도로 판정한다.

`src/resource-zones.mjs`가 이 대응표와 경로 식별을 담당한다. `/api/notes/a`와 엔진의 `/notes/a`를 같은 메모 자원으로 연결하되, 비슷한 접두어·추가 하위 경로·쿼리 선택자는 식별하지 않는다. 메모 ID를 UUID로 제한하는 코드는 이 식별기에 넣지 않는다.

`docs/DECIDER_REQUEST.md`의 요청 항목은 그대로 유지한다. `resourceId`, `role`, `identity`, `device` 같은 임의 항목을 판정기 요청에 추가하지 않는다. 이후 판정기는 기존의 `service`, `method`, `path`, `route`를 대조하며 소유자는 최종 API에서 비교한다.

제작 1에서 메모 API는 `X-Resource-Zone: student_notes`를 응답 헤더에 붙인다. 이 값은 요청의 클라이언트 구역·역할 헤더가 아니라 서버의 경로 대응표에서 구한다. 기존 로그인·소유자 검사와 메모 주소, 저장된 내용, 화면 메뉴는 변경하지 않는다.

## 판정기에서 허용하는 경로

| service | method | 실제 API 경로 | 가상 엔진 경로 |
|---|---|---|---|
| notes | GET·PUT·DELETE | /api/notes/:id | /notes/:id |
| notices | GET | /api/notices | /notices |
| notices | GET | /api/notices/:id | /notices/:id |

각 메서드와 `route` 값이 실제 `path`와 맞아야 한다. 예를 들어 `/notes/demo`의 GET은 `route: 'GET /notes/:id'`와 짝지어야 한다. `service`만 notes로 바꾸거나 다른 서비스의 route를 붙여도 통과하지 않는다. 판정기는 `queryLength`가 0인 경우만 허용하고, 모호한 인코딩·추가 경로·예약 기능명을 거부한다.

공지의 쓰기와 instructor 서비스는 판정기에서 모두 거부한다. 강사의 공지 수정은 `/api/admin/notices`의 POST 또는 `/api/admin/notices/:id`의 PUT·DELETE에서 처리하며, 이 관리 경로는 판정기 allowedRoutes에 넣지 않는다.

## 최종 API 검사와 저장 공간

공지·강사 자료 API는 기존 로그인 검증 도우미를 재사용한다. 쿠키 요청의 동일 출처 검사도 유지하며, 본문의 role·userId 또는 역할 헤더를 권한 근거로 읽지 않는다.

- 공개 공지 API는 로그인 후 GET으로만 읽는다. 강사라도 공개 경로의 쓰기는 `NOTICE_READ_ONLY`로 거부한다.
- 관리 경로와 강사 자료 API는 검증된 userId로 `vault_resource_roles`의 활성 instructor 행을 확인한다. 행이 없으면 `INSTRUCTOR_REQUIRED`, 표에 접근할 수 없으면 안전한 오류를 반환한다.
- 강사 자료는 활성 역할뿐 아니라 저장된 owner_id와 검증된 userId도 대조한다. 다른 소유자의 자료는 반환하지 않는다.
- 메모 API는 기존과 같이 검증된 사용자만 자기 자료를 다룬다. 판정기의 ID 없는 목록 거부와 기존 브라우저의 자기 메모 목록 기능을 혼동하지 않는다.

새 표는 `sql/step08-resource-zones.sql`로 준비한다. 이 프로젝트는 하나의 교육 자료실에 대한 구역 구분이며, 여러 반의 소속을 따로 등록해 분리하는 기능을 추가했다고 주장하지 않는다. 준비 SQL을 실제 DB에 적용하고 8단계를 배포하기 전에는 이 문서만으로 실제 API 검증이 완료됐다고 기록하지 않는다.

변경 전에는 사용자가 연습계정 A와 B로 각각 실제 자료실의 읽기 확인을 수행했다. 두 캡처에 자기 메모 200 / 상대 메모 404가 표시됐고, 계정 구분은 사용자 설명과 파일명에 근거한다. 이는 변경 전 단건 메모 조회의 확인이며, 8단계의 공지·강사 자료 권한 시험으로 확대하지 않는다.
