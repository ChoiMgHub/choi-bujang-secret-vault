// Public project URL and publishable key only. Password/session handling belongs to the official SDK.
(() => {
  const form = document.querySelector('#login-form');
  const email = document.querySelector('#login-email');
  const password = document.querySelector('#login-password');
  const loginButton = document.querySelector('#login-button');
  const logoutButton = document.querySelector('#logout-button');
  const status = document.querySelector('#auth-status');
  const errorBox = document.querySelector('#auth-error');
  const notes = document.querySelector('#notes');
  let busy = false;
  let renderVersion = 0;
  let noteRequest;

  function noteMessage(text) {
    const item = document.createElement('li');
    item.textContent = text;
    notes.replaceChildren(item);
  }

  async function loadNotes(session, version) {
    const controller = new AbortController();
    noteRequest = controller;
    noteMessage('가상 메모를 불러오는 중입니다.');
    try {
      const response = await fetch('/api/notes', { cache: 'no-store',
        headers: { Authorization: `Bearer ${session.access_token}` }, signal: controller.signal });
      if (version !== renderVersion) return;
      if (response.status === 401 || response.status === 403) {
        noteMessage('로그인 정보를 확인하지 못했습니다. 로그아웃한 뒤 다시 로그인해 주세요.');
        return;
      }
      if (!response.ok) throw new Error('notes_unavailable');
      const data = await response.json();
      if (version !== renderVersion) return;
      if (!Array.isArray(data.notes)) throw new Error('invalid_notes');
      notes.replaceChildren(...data.notes.map(note => {
        const item = document.createElement('li');
        const title = document.createElement('strong');
        const content = document.createElement('span');
        title.textContent = note.title;
        content.textContent = note.content;
        item.append(title, content);
        return item;
      }));
    } catch (error) {
      if (version === renderVersion && error?.name !== 'AbortError') {
        noteMessage('서버 자료를 불러오지 못했습니다. 잠시 후 새로고침해 주세요.');
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
    const version = ++renderVersion;
    noteRequest?.abort();
    notes.replaceChildren();
    const signedIn = Boolean(session?.user?.id);
    notes.hidden = !signedIn;
    form.hidden = signedIn;
    logoutButton.hidden = !signedIn;
    status.textContent = signedIn
      ? `로그인 중: ${session.user.email || '인증된 사용자'}`
      : '로그인하지 않은 상태입니다.';
    password.value = '';
    // No SDK calls inside the synchronous auth callback; this uses the supplied token.
    if (signedIn && session.access_token) void loadNotes(session, version);
  }

  function loginError(error) {
    if (error?.code === 'invalid_credentials') return '이메일 또는 비밀번호를 확인해 주세요.';
    if (error?.code === 'email_not_confirmed') return '이메일 확인이 완료되지 않은 계정입니다. Supabase에서 계정 확인 상태를 확인해 주세요.';
    if (error?.status === 429) return '로그인 요청이 많습니다. 잠시 기다린 뒤 다시 시도해 주세요.';
    if (error?.name === 'AuthRetryableFetchError' || error instanceof TypeError) return '인증 서버에 연결하지 못했습니다. 인터넷 연결을 확인하고 다시 시도해 주세요.';
    return '로그인에 실패했습니다. 계정 설정을 확인하거나 잠시 후 다시 시도해 주세요.';
  }

  try {
    const client = window.supabase.createClient(
      'https://prplojzcswmpaqhcnmwl.supabase.co',
      'sb_publishable_z3tY48lOSOJ8NqLhTpuTXg_aNgHDGKd',
      { auth: { storage: window.sessionStorage, persistSession: true,
        autoRefreshToken: true, detectSessionInUrl: false } },
    );

    // Keep this callback synchronous: no awaited SDK requests inside it.
    client.auth.onAuthStateChange((_event, session) => renderSession(session));
    setBusy(false);

    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (busy) return;
      errorBox.textContent = '';
      setBusy(true);
      try {
        const pending = client.auth.signInWithPassword({ email: email.value.trim(), password: password.value });
        password.value = '';
        const { data, error } = await pending;
        if (error) { errorBox.textContent = loginError(error); return; }
        if (!data?.session?.user?.id) { errorBox.textContent = '로그인 세션을 확인하지 못했습니다. 다시 시도해 주세요.'; return; }
        renderSession(data.session);
      } catch (error) {
        errorBox.textContent = loginError(error);
      } finally {
        password.value = '';
        setBusy(false);
      }
    });

    logoutButton.addEventListener('click', async () => {
      if (busy) return;
      errorBox.textContent = '';
      setBusy(true);
      try {
        const { error } = await client.auth.signOut({ scope: 'local' });
        if (error) { errorBox.textContent = '서버의 로그아웃 처리를 확인하지 못했습니다. 연결을 확인한 뒤 다시 시도해 주세요.'; return; }
        renderSession(null);
        status.textContent = '로그아웃했습니다.';
      } catch {
        errorBox.textContent = '로그아웃 요청에 실패했습니다. 인터넷 연결을 확인하고 다시 시도해 주세요.';
      } finally {
        setBusy(false);
      }
    });
  } catch {
    ++renderVersion;
    noteRequest?.abort();
    notes.replaceChildren();
    notes.hidden = true;
    form.hidden = true;
    logoutButton.hidden = true;
    status.textContent = '로그인 기능을 준비하지 못했습니다.';
    errorBox.textContent = '인증 화면을 불러오지 못했습니다. 새로고침한 뒤 다시 시도해 주세요.';
  }
})();
