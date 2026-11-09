// Installation UI never grants device approval or touches authentication state.
(() => {
  const install = document.querySelector('#app-install');
  const installStatus = document.querySelector('#app-install-status');
  const connection = document.querySelector('#connection-status');
  let offer = null;
  const standalone = () => window.matchMedia?.('(display-mode: standalone)').matches === true;
  function showInstallState() {
    installStatus.textContent = standalone() ? '앱 화면으로 이용 중입니다. 기기 승인은 별도로 확인합니다.' : '웹 화면으로 이용 중입니다.';
  }
  function showConnection() {
    connection.textContent = navigator.onLine === false
      ? '오프라인입니다. 보호 자료를 읽으려면 다시 연결해 주세요.'
      : '서버 연결 상태에서 이용해 주세요. 보호 자료는 오프라인 저장하지 않습니다.';
  }
  window.addEventListener('beforeinstallprompt', event => {
    event.preventDefault(); offer = event; install.hidden = standalone();
  });
  install.addEventListener('click', async () => {
    if (!offer) return;
    const current = offer; offer = null; install.hidden = true;
    try {
      await current.prompt();
      const choice = await current.userChoice;
      installStatus.textContent = choice.outcome === 'accepted'
        ? '앱 설치를 요청했습니다. 기기 승인은 별도입니다.'
        : '웹 화면으로 계속 이용합니다.';
    } catch { installStatus.textContent = '브라우저 메뉴에서 앱 설치 가능 여부를 확인해 주세요.'; }
  });
  window.addEventListener('appinstalled', () => { offer = null; install.hidden = true; showInstallState(); });
  window.addEventListener('online', showConnection);
  window.addEventListener('offline', showConnection);
  showInstallState(); showConnection();
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/service-worker.js', { scope: '/', updateViaCache: 'none' }).catch(() => {
      connection.textContent = '오프라인 안내를 준비하지 못했습니다. 서버에 연결해 이용해 주세요.';
    });
  }
})();
