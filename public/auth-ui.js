// Public project URL and publishable key only. Password/session handling belongs to the official SDK.
(() => {
  const form = document.querySelector('#login-form');
  const email = document.querySelector('#login-email');
  const password = document.querySelector('#login-password');
  const loginButton = document.querySelector('#login-button');
  const logoutButton = document.querySelector('#logout-button');
  const status = document.querySelector('#auth-status');
  const errorBox = document.querySelector('#auth-error');
  let busy = false;

  function setBusy(value) {
    busy = value;
    loginButton.disabled = value;
    logoutButton.disabled = value;
    email.disabled = value;
    password.disabled = value;
  }

  function renderSession(session) {
    const signedIn = Boolean(session?.user?.id);
    form.hidden = signedIn;
    logoutButton.hidden = !signedIn;
    status.textContent = signedIn
      ? `로그인 중: ${session.user.email || '인증된 사용자'}`
      : '로그인하지 않은 상태입니다.';
    password.value = '';
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
    form.hidden = true;
    logoutButton.hidden = true;
    status.textContent = '로그인 기능을 준비하지 못했습니다.';
    errorBox.textContent = '인증 화면을 불러오지 못했습니다. 새로고침한 뒤 다시 시도해 주세요.';
  }
})();
