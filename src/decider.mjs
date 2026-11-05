// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계: 등록 기기의 정상 요청을 허용하고 미등록·등록 값 누락은 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
// 운영 엔진이 확인해서 전달한 요청을 판단합니다.
export const RULE_IDS = Object.freeze(['device_registered']);

export async function decide(request) {
  const registered = request.deviceRegistered === true;

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: registered ? 'allow' : 'deny',
    reasonCode: registered ? 'approved' : 'device_not_registered',
    ruleIds: ['device_registered'],
  };
}