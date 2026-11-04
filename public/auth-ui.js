// Authentication stays on the server. The browser receives user metadata only.
(() => {
  const form = document.querySelector('#login-form');
  const email = document.querySelector('#login-email');
  const password = document.querySelector('#login-password');
  const loginButton = document.querySelector('#login-button');
  const logoutButton = document.querySelector('#logout-button');
  const status = document.querySelector('#auth-status');
  const errorBox = document.querySelector('#auth-error');
  const notes = document.querySelector('#notes');
  const panel = document.querySelector('#memo-panel');
  const memoForm = document.querySelector('#memo-form');
  const memoTitle = document.querySelector('#memo-title');
  const memoBody = document.querySelector('#memo-body');
  const memoSave = document.querySelector('#memo-save');
  const memoCancel = document.querySelector('#memo-cancel');
  const memoMessage = document.querySelector('#memo-message');
  const ownerCheck = document.querySelector('#owner-check');
  const ownerCheckResult = document.querySelector('#owner-check-result');
  let busy = false;
  let memoBusy = false;
  let activeSession = null;
  let restorePromise = null;
  let refreshTimer;
  let loggingOut = false;
  let editingId = null;
  let renderVersion = 0;
  const requests = new Set();
  let cardButtons = [];

  function noteMessage(text) {
    const item = document.createElement('li');
    item.textContent = text;
    notes.replaceChildren(item);
    cardButtons = [];
  }
  function setMemoBusy(value) {
    memoBusy = value;
    for (const control of [memoTitle, memoBody, memoSave, memoCancel, ownerCheck, ...cardButtons]) {
      control.disabled = value || !activeSession;
    }
  }
  function resetEditor() {
    editingId = null;
    memoTitle.value = '';
    memoBody.value = '';
    memoSave.textContent = '메모 추가';
    memoCancel.hidden = true;
  }
  function staleView() { const error = new Error('stale_view'); error.name = 'AbortError'; return error; }
  function apiError(statusCode) {
    if (statusCode === 401 || statusCode === 403) return '로그인 정보를 확인하지 못했습니다. 로그아웃한 뒤 다시 로그인해 주세요.';
    if (statusCode === 404) return '메모를 찾지 못했습니다. 목록을 새로고침해 주세요.';
    if (statusCode === 409) return '같은 번호의 메모가 이미 있습니다. 새로고침해서 저장 여부를 확인해 주세요.';
    if (statusCode === 400 || statusCode === 413) return '제목은 1~200자, 내용은 10,000자 이내로 입력해 주세요.';
    return '서버에서 메모를 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.';
  }
  async function api(path, { method = 'GET', data, session = activeSession, version = renderVersion } = {}) {
    if (!session?.user?.id || version !== renderVersion) throw staleView();
    const controller = new AbortController();
    requests.add(controller);
    try {
      const headers = { 'x-requested-with': 'vault-ui' };
      if (data !== undefined) headers['Content-Type'] = 'application/json';
      let response = await fetch(path, { method, credentials: 'same-origin', cache: 'no-store', headers,
        body: data === undefined ? undefined : JSON.stringify(data), signal: controller.signal });
      if (response.status === 401 && version === renderVersion) {
        const fresh = await restoreSession(true);
        if (!fresh?.user || fresh.user.id !== session.user.id || version !== renderVersion) throw staleView();
        response = await fetch(path, { method, credentials: 'same-origin', cache: 'no-store', headers,
          body: data === undefined ? undefined : JSON.stringify(data), signal: controller.signal });
      }
      if (version !== renderVersion) throw staleView();
      if (!response.ok) throw new Error(apiError(response.status));
      const payload = await response.json();
      if (version !== renderVersion) throw staleView();
      return payload;
    } finally { requests.delete(controller); }
  }
  function validNote(note) {
    return note && typeof note.id === 'string' && typeof note.title === 'string' && typeof note.body === 'string';
  }
  async function checkOwnerRead() {
    if (memoBusy || !activeSession) return;
    const fixtures = {
      'learner-a@example.com': ['10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001'],
      'learner-b@example.com': ['20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001'],
    };
    const ids = fixtures[activeSession.user.email?.toLowerCase()];
    if (!ids) { ownerCheckResult.textContent = '이 확인은 A·B 연습 계정 전용입니다.'; return; }
    const version = renderVersion;
    const session = activeSession;
    const controller = new AbortController();
    setMemoBusy(true); ownerCheckResult.textContent = '내 메모와 상대 메모의 조회 응답을 확인하는 중입니다.';
    try {
      const own = await api(`/api/notes/${ids[0]}`, { session, version });
      if (!validNote(own) || own.id !== ids[0]) throw new Error('missing_fixture');
      requests.add(controller);
      const response = await fetch(`/api/notes/${ids[1]}`, { method: 'GET', credentials: 'same-origin', cache: 'no-store',
        headers: { 'x-requested-with': 'vault-ui' }, signal: controller.signal });
      if (version !== renderVersion) throw staleView();
      let payload;
      if (response.status === 404 && response.headers.get('content-type')?.includes('application/json')) {
        try { payload = await response.json(); } catch { /* Not a verified denial. */ }
      }
      if (version !== renderVersion) throw staleView();
      const denied = response.status === 404 && payload?.error === 'NOT_FOUND'
        && Object.keys(payload).length === 1;
      ownerCheckResult.textContent = denied
        ? '확인 완료: 내 메모 조회 200 / 상대 메모 조회 404(접근 거부). A·B 두 계정에서 각각 확인하세요.'
        : `확인 필요: 상대 메모 조회 HTTP ${response.status}. 차단 성공으로 기록하지 않았습니다.`;
    } catch (error) {
      if (version === renderVersion && error.name !== 'AbortError') {
        ownerCheckResult.textContent = '확인하지 못했습니다. 내 시험 메모가 있는지 확인하고 다시 로그인해 주세요.';
      }
    } finally {
      requests.delete(controller);
      if (version === renderVersion) setMemoBusy(false);
    }
  }
  async function editNote(note) {
    if (memoBusy) return;
    const version = renderVersion;
    setMemoBusy(true); memoMessage.textContent = '';
    try {
      const latest = await api(`/api/notes/${encodeURIComponent(note.id)}`, { version });
      if (!validNote(latest)) throw new Error('메모 형식을 확인하지 못했습니다.');
      editingId = latest.id;
      memoTitle.value = latest.title;
      memoBody.value = latest.body;
      memoSave.textContent = '수정 저장';
      memoCancel.hidden = false;
      memoMessage.textContent = '제목이나 내용을 바꾼 뒤 수정 저장을 누르세요.';
    } catch (error) {
      if (version === renderVersion && error.name !== 'AbortError') memoMessage.textContent = error.message;
    } finally { if (version === renderVersion) setMemoBusy(false); }
  }
  async function deleteNote(note) {
    if (memoBusy || !window.confirm('이 메모를 삭제할까요?')) return;
    const version = renderVersion;
    setMemoBusy(true); memoMessage.textContent = '';
    try {
      await api(`/api/notes/${encodeURIComponent(note.id)}`, { method: 'DELETE', version });
      if (editingId === note.id) resetEditor();
      await loadNotes(activeSession, version);
      if (version === renderVersion) memoMessage.textContent = '메모를 삭제했습니다.';
    } catch (error) {
      if (version === renderVersion && error.name !== 'AbortError') memoMessage.textContent = error.message;
    } finally { if (version === renderVersion) setMemoBusy(false); }
  }
  async function loadNotes(session, version) {
    noteMessage('가상 메모를 불러오는 중입니다.');
    try {
      const data = await api('/api/notes', { session, version });
      if (!Array.isArray(data) || data.some(note => !validNote(note))) throw new Error('메모 목록 형식을 확인하지 못했습니다.');
      if (!data.length) { noteMessage('아직 내가 작성한 메모가 없습니다. 위에서 새 연습 메모를 추가하세요.'); return; }
      cardButtons = [];
      notes.replaceChildren(...data.map(note => {
        const item = document.createElement('li');
        const title = document.createElement('strong');
        const content = document.createElement('span');
        const actions = document.createElement('div');
        actions.className = 'memo-actions';
        title.textContent = note.title;
        content.textContent = note.body;
        const edit = document.createElement('button');
        edit.type = 'button'; edit.textContent = '수정';
        edit.addEventListener('click', () => editNote(note));
        const remove = document.createElement('button');
        remove.type = 'button'; remove.textContent = '삭제';
        remove.addEventListener('click', () => deleteNote(note));
        cardButtons.push(edit, remove);
        actions.append(edit, remove);
        item.append(title, content, actions);
        return item;
      }));
      setMemoBusy(memoBusy);
    } catch (error) {
      if (version === renderVersion && error.name !== 'AbortError') {
        noteMessage(error.message || '서버 자료를 불러오지 못했습니다. 새로고침해 주세요.');
      }
    }
  }
  function setBusy(value) {
    busy = value;
    loginButton.disabled = value;
    logoutButton.disabled = value;
    email.disabled = value;
    password.disabled = value;
  }
  function renderSession(session) {
    const previousUser = activeSession?.user?.id;
    const version = ++renderVersion;
    for (const controller of requests) controller.abort();
    requests.clear();
    clearTimeout(refreshTimer);
    activeSession = session;
    ownerCheckResult.textContent = '';
    notes.replaceChildren(); cardButtons = [];
    const signedIn = Boolean(session?.user?.id);
    panel.hidden = !signedIn;
    notes.hidden = !signedIn;
    form.hidden = signedIn;
    logoutButton.hidden = !signedIn;
    status.textContent = signedIn ? `로그인 중: ${session.user.email || '인증된 사용자'}` : '로그인하지 않은 상태입니다.';
    password.value = '';
    if (!signedIn || previousUser !== session.user.id) { resetEditor(); memoMessage.textContent = ''; }
    setMemoBusy(false);
    if (signedIn) { scheduleSession(session); void loadNotes(session, version); }
  }
  function loginError(error) {
    if (error?.code === 'INVALID_CREDENTIALS') return '이메일 또는 비밀번호를 확인해 주세요.';
    if (error?.code === 'EMAIL_NOT_CONFIRMED') return '이메일 확인이 완료되지 않은 계정입니다.';
    if (error?.status === 429) return '로그인 요청이 많습니다. 잠시 기다린 뒤 다시 시도해 주세요.';
    if (error?.code === 'AUTH_UNAVAILABLE' || error instanceof TypeError) return '인증 서버에 연결하지 못했습니다. 잠시 후 다시 시도해 주세요.';
    return '로그인에 실패했습니다. 계정 설정을 확인하거나 잠시 후 다시 시도해 주세요.';
  }
  async function authRequest(method, data) {
    const headers = { 'x-requested-with': 'vault-ui' };
    if (data !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetch('/api/auth', { method, credentials: 'same-origin',
      cache: 'no-store', headers, body: data === undefined ? undefined : JSON.stringify(data) });
    let payload;
    try { payload = await response.json(); } catch { /* Error below contains no upstream data. */ }
    if (!response.ok || !payload || !Object.hasOwn(payload, 'user')) {
      const error = new Error('auth_request_failed');
      error.code = typeof payload?.error === 'string' ? payload.error : 'AUTH_UNAVAILABLE';
      error.status = response.status;
      throw error;
    }
    if (payload.user === null) return null;
    if (typeof payload.user?.id !== 'string' || typeof payload.user?.email !== 'string'
        || !Number.isSafeInteger(payload.expiresAt)) throw new Error('invalid_auth_response');
    return { user: { id: payload.user.id, email: payload.user.email }, expiresAt: payload.expiresAt };
  }
  function scheduleSession(session) {
    clearTimeout(refreshTimer);
    if (!session?.user || loggingOut) return;
    const delay = Math.max(1000, Math.min(20 * 60 * 1000, session.expiresAt * 1000 - Date.now() - 60000));
    refreshTimer = setTimeout(() => { void restoreSession(true).catch(() => {}); }, delay);
    refreshTimer?.unref?.();
  }
  function restoreSession(background = false) {
    if (restorePromise) return restorePromise;
    const version = renderVersion;
    restorePromise = (async () => {
      const session = await authRequest('GET');
      if (loggingOut || version !== renderVersion) return null;
      if (!background || session?.user?.id !== activeSession?.user?.id) renderSession(session);
      else { activeSession = session; scheduleSession(session); }
      return session;
    })().finally(() => { restorePromise = null; });
    return restorePromise;
  }
  ownerCheck.addEventListener('click', checkOwnerRead);
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (busy) return;
    errorBox.textContent = ''; setBusy(true);
    try {
      const pending = authRequest('POST', { email: email.value.trim(), password: password.value });
      password.value = '';
      const session = await pending;
      if (!session?.user) throw new Error('missing_auth_session');
      renderSession(session);
    } catch (error) { errorBox.textContent = loginError(error); }
    finally { password.value = ''; setBusy(false); }
  });
  logoutButton.addEventListener('click', async () => {
    if (busy) return;
    errorBox.textContent = ''; setBusy(true); loggingOut = true;
    clearTimeout(refreshTimer);
    try {
      // Let an in-flight refresh finish before logout clears/revokes its cookies.
      if (restorePromise) await restorePromise.catch(() => {});
      await authRequest('DELETE');
      renderSession(null); status.textContent = '로그아웃했습니다.';
    } catch {
      errorBox.textContent = '서버의 로그아웃 처리를 확인하지 못했습니다. 잠시 후 다시 시도해 주세요.';
    } finally { loggingOut = false; scheduleSession(activeSession); setBusy(false); }
  });
  memoForm.addEventListener('submit', async event => {
    event.preventDefault(); if (memoBusy || !activeSession) return;
    const version = renderVersion;
    const id = editingId;
    const data = { title: memoTitle.value, body: memoBody.value };
    memoMessage.textContent = ''; setMemoBusy(true);
    try {
      await api(id ? `/api/notes/${encodeURIComponent(id)}` : '/api/notes', {
        method: id ? 'PUT' : 'POST', data, version,
      });
      resetEditor();
      await loadNotes(activeSession, version);
      if (version === renderVersion) memoMessage.textContent = id ? '메모를 수정했습니다.' : '메모를 추가했습니다.';
    } catch (error) {
      if (version === renderVersion && error.name !== 'AbortError') memoMessage.textContent = error.message;
    } finally { if (version === renderVersion) setMemoBusy(false); }
  });
  memoCancel.addEventListener('click', () => { if (!memoBusy) { resetEditor(); memoMessage.textContent = ''; } });
  setBusy(true);
  void restoreSession().catch(() => {
    renderSession(null);
    errorBox.textContent = '로그인 상태를 확인하지 못했습니다. 잠시 후 다시 로그인해 주세요.';
  }).finally(() => { setBusy(false); });
})();
