// This is a student regression catalog, not the operator's 41-attack list.
const item=(caseId,step,label,method,path,expectedStatus,expectedResult,extra={})=>Object.freeze({
  caseId,step,label,method,path,expectedStatus,expectedResult,source:'live_api',...extra,
});
export const VERIFICATION_CASES=Object.freeze([
  item('public_source','1~2','공개 메모 원문 제거','GET','/data.json','404','PUBLIC_SOURCE_ABSENT'),
  item('anonymous_notes','3','미로그인 메모 거부','GET','/api/notes','401','AUTH_REQUIRED'),
  item('own_note','4','자기 시험 메모 조회','GET','/api/notes/:own','200','NOTE_SHAPE_MATCHED',{needsFixtures:true}),
  item('foreign_note','4','상대 시험 메모 거부','GET','/api/notes/:other','404','NOT_FOUND',{needsFixtures:true}),
  item('direct_database','5','원본 DB 공개 키 읽기 거부','GET','Supabase /rest/v1/vault_notes','401/403','42501'),
  item('notice_read','8','반 공지 읽기','GET','/api/notices/80000000-0000-4000-8000-000000000001','200','NOTICE_SHAPE_MATCHED'),
  item('notice_write','8','학생 공지 쓰기 거부','POST','/api/notices','403','NOTICE_READ_ONLY'),
  item('instructor_read','8','학생 강사 자료 거부','GET','/api/instructor/80000000-0000-4000-8000-000000000002','403','INSTRUCTOR_REQUIRED'),
  item('admin_write','8','학생 강사 관리 거부','POST','/api/admin/notices','403','INSTRUCTOR_REQUIRED'),
  item('restore_method','10','복구 API의 GET 거부','GET','/api/restore','405','METHOD_NOT_ALLOWED'),
  item('backup_snapshot','10','B 사본 재검증 조회','GET','/api/operations','200','BACKUP_VERIFIED',{account:'B'}),
  item('approved_device','11','현재 세션 서버 승인 확인','GET','/api/device','200','approved'),
  item('anonymous_operations','11~12','미로그인 작전실 거부','GET','/api/operations','401','AUTH_REQUIRED'),
  ...[
    ['decider_allow','6','등록 기기 정상 판정','allow'],
    ['decider_deny','6','미등록 기기 거부 판정','deny'],
    ['decider_step_up','7','복합 이상 추가 확인','step_up'],
    ['decider_recheck','7','가상 재확인 후 허용','allow'],
    ['detect_120','9','10분 안 120건 관찰','observe'],
    ['detect_121','9','10분 안 121건 회수 제안','propose_revocation'],
    ['detect_users','9','다른 사용자 조회 분리','observe'],
    ['detect_slow','9','10분 밖 느린 조회','observe'],
  ].map(([id,step,label,result])=>item(id,step,label,'POST','/api/operations-rule','200',result,{source:'student_fixture_api'})),
  item('manual_pending','11','새 미승인 세션의 메모 직접 조회','GET','/api/notes','403','DEVICE_APPROVAL_REQUIRED',{source:'manual'}),
  item('manual_revocation','9~11','별도 세션 철회 후 차단','GET','/api/notes','403','DEVICE_APPROVAL_REQUIRED',{source:'manual'}),
  item('manual_restore_owner','10','A의 B 복구 요청 거부','POST','/api/restore','404','NOT_FOUND',{source:'manual'}),
]);
export const caseById=id=>VERIFICATION_CASES.find(value=>value.caseId===id);
export const emptyVerificationRows=()=>VERIFICATION_CASES.map(value=>({
  caseId:value.caseId,source:value.source,method:value.method,path:value.path,
  expectedStatus:value.expectedStatus,expectedResult:value.expectedResult,
  state:'not_executed',actualStatus:null,actualResult:null,requestId:null,checkedAt:null,
}));
