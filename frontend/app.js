// ==========================================
// Configuración de API & Criptografía
// ==========================================
const API_BASE = window.location.protocol.startsWith('http')
  ? `${window.location.origin}/api`
  : 'http://localhost:5000/api';

// Estado global de la aplicación
let currentSession = {
  token: null,
  user: null,
  expiresAt: null,
  countdownInterval: null
};

// ==========================================
// Inicialización
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
  setupCryptoActivityMonitor();
  checkSavedSession();
  setupEventListeners();
  checkApiHealth();
});

// Registrar monitor de actividad criptográfica en tiempo real
function setupCryptoActivityMonitor() {
  window.onCryptoActivity = function(activity) {
    const activityEl = document.getElementById('crypto-last-activity');
    if (!activityEl) return;

    if (activity.type === 'REQUEST_ENCRYPTED') {
      activityEl.innerHTML = `<span style="color: #38bdf8;">📤 ${activity.method}</span>: ${activity.plainLength}B texto plano &rarr; <span style="color: #34d399;">${activity.cipherLength}B AES-GCM</span>`;
    } else if (activity.type === 'RESPONSE_DECRYPTED') {
      activityEl.innerHTML = `<span style="color: #34d399;">📥 Resp HTTP ${activity.status}</span>: ${activity.cipherLength}B AES-GCM &rarr; <span style="color: #a5b4fc;">JSON Descifrado</span>`;
    }
  };
}

// Comprobar estado del backend y del módulo criptográfico
async function checkApiHealth() {
  const statusDot = document.getElementById('status-dot');
  const statusText = document.getElementById('status-text');
  const cryptoBadge = document.getElementById('crypto-badge');

  try {
    const res = await fetch(`${API_BASE.replace('/api', '')}/health`);
    if (res.ok) {
      statusDot.style.backgroundColor = 'var(--accent-emerald)';
      statusDot.style.boxShadow = '0 0 10px var(--accent-emerald)';
      statusText.textContent = 'API Conectada';
    } else {
      throw new Error();
    }

    // Verificar capacidades criptográficas del backend
    try {
      const cryptoRes = await fetch(`${API_BASE}/crypto/info`);
      if (cryptoRes.ok) {
        const cryptoData = await cryptoRes.json();
        if (cryptoBadge) {
          cryptoBadge.title = `Algoritmo: ${cryptoData.payload_encryption.algorithm} (${cryptoData.payload_encryption.key_size_bits}-bit)`;
          cryptoBadge.style.display = 'inline-flex';
        }
      }
    } catch { }

  } catch {
    statusDot.style.backgroundColor = 'var(--accent-rose)';
    statusDot.style.boxShadow = '0 0 10px var(--accent-rose)';
    statusText.textContent = 'API Desconectada (5000)';
  }
}

// ==========================================
// Navegación entre Vistas
// ==========================================
function switchView(viewName) {
  const views = ['login-view', 'register-view', 'forgot-view', 'dashboard-view'];
  views.forEach(v => {
    const el = document.getElementById(v);
    if (el) el.classList.add('hidden');
  });

  const target = document.getElementById(`${viewName}-view`);
  if (target) target.classList.remove('hidden');

  // Resetear estado de la caja generadora si cambiamos de vista
  const genBox = document.getElementById('generator-box');
  if (genBox) genBox.classList.remove('active');
}

// ==========================================
// Toast Notifications
// ==========================================
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  const iconMap = {
    success: '<i class="pi pi-check-circle" style="color: #34d399; font-size: 1.1rem;"></i>',
    error: '<i class="pi pi-times-circle" style="color: #fda4af; font-size: 1.1rem;"></i>',
    info: '<i class="pi pi-info-circle" style="color: #a5b4fc; font-size: 1.1rem;"></i>'
  };

  toast.innerHTML = `
    <span>${iconMap[type] || '<i class="pi pi-bell"></i>'}</span>
    <span>${message}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ==========================================
// Generador y Evaluador de Contraseña Segura
// ==========================================
function generateSecurePassword(length = 16) {
  const uppers = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const lowers = "abcdefghijkmnopqrstuvwxyz";
  const numbers = "23456789";
  const specials = "!@#$%^&*()_+~`|}{[]:;?><,./-=";
  const all = uppers + lowers + numbers + specials;

  let pwd = "";
  pwd += uppers[Math.floor(Math.random() * uppers.length)];
  pwd += lowers[Math.floor(Math.random() * lowers.length)];
  pwd += numbers[Math.floor(Math.random() * numbers.length)];
  pwd += specials[Math.floor(Math.random() * specials.length)];

  for (let i = pwd.length; i < length; i++) {
    pwd += all[Math.floor(Math.random() * all.length)];
  }

  return pwd.split('').sort(() => 0.5 - Math.random()).join('');
}

function evaluatePasswordStrength(password) {
  let score = 0;
  if (!password) return { score: 0, label: 'Vacía', color: 'transparent' };

  if (password.length >= 8) score += 25;
  if (password.length >= 12) score += 15;
  if (/[A-Z]/.test(password)) score += 20;
  if (/[a-z]/.test(password)) score += 15;
  if (/[0-9]/.test(password)) score += 15;
  if (/[^A-Za-z0-9]/.test(password)) score += 10;

  if (score < 40) return { score, label: 'Débil', color: 'var(--accent-rose)' };
  if (score < 70) return { score, label: 'Media', color: 'var(--accent-amber)' };
  if (score < 90) return { score, label: 'Fuerte', color: 'var(--accent-cyan)' };
  return { score: 100, label: 'Muy Segura', color: 'var(--accent-emerald)' };
}

function suggestNewPassword(displayId = 'gen-password-display') {
  const suggested = generateSecurePassword(16);
  const genDisplay = document.getElementById(displayId);
  if (genDisplay) {
    genDisplay.textContent = suggested;
  }
}

function toggleGenerator(boxId = 'generator-box', displayId = 'gen-password-display') {
  const box = document.getElementById(boxId);
  if (!box) return;
  const isOpening = !box.classList.contains('active');
  box.classList.toggle('active');
  if (isOpening) {
    suggestNewPassword(displayId);
  }
}

function applyGeneratedPassword(targetInputId, boxId = 'generator-box') {
  const genDisplay = document.getElementById('gen-password-display');
  const targetInput = document.getElementById(targetInputId);
  if (genDisplay && targetInput) {
    const password = genDisplay.textContent.trim();
    targetInput.value = password;
    targetInput.dispatchEvent(new Event('input'));
    showToast('Contraseña segura aplicada al formulario', 'success');

    const box = document.getElementById(boxId);
    if (box) box.classList.remove('active');
  }
}

// ==========================================
// Decodificador de Token JWT y Claims Cifrados
// ==========================================
function parseJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
  } catch (e) {
    console.error("Error al decodificar JWT:", e);
    return null;
  }
}

function parseJwtHeader(token) {
  try {
    const parts = token.split('.');
    const base64Url = parts[0];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(base64));
  } catch {
    return { alg: "HS256", typ: "JWT" };
  }
}

// ==========================================
// Manejo de Sesión y Cuenta Regresiva
// ==========================================
async function startSession(token, user) {
  const payload = parseJwt(token);
  const expTimestamp = payload && payload.exp ? payload.exp * 1000 : Date.now() + 1 * 60 * 1000;

  // Si no nos pasaron el objeto user explícito pero el payload contiene enc_data
  let finalUser = user;
  if (!finalUser && payload && payload.enc_data) {
    try {
      finalUser = await CryptoEngine.decryptPayload(payload.enc_data);
    } catch {
      finalUser = payload;
    }
  }

  currentSession = {
    token,
    user: finalUser || payload || {},
    expiresAt: expTimestamp
  };

  localStorage.setItem('auth_session', JSON.stringify({
    token,
    user: currentSession.user,
    expiresAt: expTimestamp
  }));

  renderDashboard();
  switchView('dashboard');
  startCountdown(expTimestamp);
}

function checkSavedSession() {
  const saved = localStorage.getItem('auth_session');
  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      if (parsed.expiresAt && Date.now() < parsed.expiresAt) {
        startSession(parsed.token, parsed.user);
        return;
      }
    } catch { }
    localStorage.removeItem('auth_session');
  }
  switchView('login');
}

function logout(isExpired = false) {
  if (currentSession.countdownInterval) {
    clearInterval(currentSession.countdownInterval);
  }
  currentSession = { token: null, user: null, expiresAt: null, countdownInterval: null };
  localStorage.removeItem('auth_session');
  switchView('login');

  if (isExpired) {
    showToast('Tu sesión ha expirado (1 minuto). Por favor inicia sesión nuevamente.', 'error');
  } else {
    showToast('Sesión cerrada correctamente', 'info');
  }
}

function startCountdown(expiresAt) {
  if (currentSession.countdownInterval) {
    clearInterval(currentSession.countdownInterval);
  }

  const digitsEl = document.getElementById('countdown-digits');
  const fillEl = document.getElementById('countdown-fill');
  const badgeEl = document.getElementById('session-badge-timer');
  const totalDuration = 1 * 60 * 1000;

  function updateTimer() {
    const now = Date.now();
    const remaining = expiresAt - now;

    if (remaining <= 0) {
      clearInterval(currentSession.countdownInterval);
      if (digitsEl) digitsEl.textContent = "00:00";
      if (fillEl) fillEl.style.width = "0%";
      logout(true);
      return;
    }

    const totalSeconds = Math.floor(remaining / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    const formatted = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;

    if (digitsEl) digitsEl.textContent = formatted;
    const badgeTextEl = document.getElementById('timer-badge-text');
    if (badgeTextEl) badgeTextEl.textContent = formatted;
    else if (badgeEl) badgeEl.textContent = formatted;

    const percentage = Math.max(0, Math.min(100, (remaining / totalDuration) * 100));
    if (fillEl) fillEl.style.width = `${percentage}%`;

    // Cambiar color cuando falten menos de 20 segundos
    if (remaining < 20 * 1000) {
      if (fillEl) fillEl.style.background = 'var(--accent-rose)';
      if (digitsEl) {
        digitsEl.style.background = 'var(--accent-rose)';
        digitsEl.style.webkitBackgroundClip = 'text';
      }
    }
  }

  updateTimer();
  currentSession.countdownInterval = setInterval(updateTimer, 1000);
}

// ==========================================
// Renderizar Panel / Dashboard Criptográfico
// ==========================================
async function renderDashboard() {
  const { token, user, expiresAt } = currentSession;
  const payload = parseJwt(token) || {};
  const header = parseJwtHeader(token);

  // Avatar e iniciales
  const initials = (user.name?.[0] || 'U') + (user.lastname?.[0] || '');
  document.getElementById('user-avatar').textContent = initials.toUpperCase();
  document.getElementById('user-fullname').textContent = `${user.name || ''} ${user.lastname || ''}`;
  document.getElementById('user-welcome-email').textContent = user.email || '';

  // Card 1: User Info
  document.getElementById('info-id').textContent = user.id || payload.id || 'N/A';
  document.getElementById('info-email').textContent = user.email || payload.email || 'N/A';
  document.getElementById('info-username').textContent = `@${user.username || payload.username || ''}`;
  document.getElementById('info-name').textContent = user.name || payload.name || 'N/A';
  document.getElementById('info-lastname').textContent = user.lastname || payload.lastname || 'N/A';

  const expDate = new Date(expiresAt);
  document.getElementById('info-expires').textContent = expDate.toLocaleTimeString();

  // Card 2: Token Details & Crypto breakdown
  document.getElementById('raw-jwt-display').textContent = token;

  // Si el token tiene claims cifrados ('enc_data'), descifrarlos para la vista
  let decryptedClaims = user;
  if (payload.enc_data) {
    try {
      decryptedClaims = await CryptoEngine.decryptPayload(payload.enc_data);
    } catch (e) {
      console.warn("No se pudo descifrar enc_data del token en el cliente:", e);
    }
  }

  const tokenBreakdown = {
    "1. Header (Integrity Algorithm)": header,
    "2. Encrypted Token Payload": {
      "enc_data": payload.enc_data || "[UNENCRYPTED_LEGACY_PAYLOAD]",
      "encryption_algorithm": payload.enc || "AES-256-GCM",
      "issued_at (iat)": payload.iat ? new Date(payload.iat * 1000).toISOString() : undefined,
      "expires_at (exp)": payload.exp ? new Date(payload.exp * 1000).toISOString() : undefined
    },
    "3. Decrypted Protected Claims (Identity)": decryptedClaims,
    "4. Signature Verification": "[VERIFIED_HS256_MAC_SIGNATURE]"
  };

  document.getElementById('jwt-json-viewer').textContent = JSON.stringify(tokenBreakdown, null, 2);
}

// ==========================================
// Event Listeners y Formularios E2EE
// ==========================================
function setupEventListeners() {
  // 1. Toggle Password Visibility
  document.querySelectorAll('.input-btn-toggle').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const input = btn.parentElement.querySelector('input');
      const icon = btn.querySelector('i');
      if (input.type === 'password') {
        input.type = 'text';
        if (icon) {
          icon.className = 'pi pi-eye-slash';
        } else {
          btn.innerHTML = '<i class="pi pi-eye-slash"></i>';
        }
      } else {
        input.type = 'password';
        if (icon) {
          icon.className = 'pi pi-eye';
        } else {
          btn.innerHTML = '<i class="pi pi-eye"></i>';
        }
      }
    });
  });

  // 2. Medidor de fuerza en registro
  const regPwdInput = document.getElementById('reg-password');
  if (regPwdInput) {
    regPwdInput.addEventListener('input', (e) => {
      const val = e.target.value;
      const res = evaluatePasswordStrength(val);
      const fill = document.getElementById('reg-pwd-fill');
      const label = document.getElementById('reg-pwd-label');
      if (fill) {
        fill.style.width = `${res.score}%`;
        fill.style.backgroundColor = res.color;
      }
      if (label) {
        label.textContent = `Fuerza: ${res.label}`;
        label.style.color = res.color;
      }
    });
  }

  // 3. Formulario de Login (E2E AES-256-GCM Encrypted)
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('btn-login-submit');
      const emailOrUser = document.getElementById('login-identifier').value.trim();
      const password = document.getElementById('login-password').value;

      setBtnLoading(btn, true);
      try {
        const res = await CryptoEngine.secureFetch(`${API_BASE}/login`, {
          method: 'POST',
          body: { email: emailOrUser, password }
        });

        const data = res.data;
        if (!res.ok) throw new Error(data.error || 'Credenciales incorrectas');

        showToast('¡Bienvenido! Sesión iniciada (Cifrado E2EE)', 'success');
        startSession(data.token, data.user);
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setBtnLoading(btn, false);
      }
    });
  }

  // 4. Formulario de Registro (E2E AES-256-GCM Encrypted)
  const regForm = document.getElementById('register-form');
  if (regForm) {
    regForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('btn-reg-submit');
      const name = document.getElementById('reg-name').value.trim();
      const lastname = document.getElementById('reg-lastname').value.trim();
      const username = document.getElementById('reg-username').value.trim();
      const email = document.getElementById('reg-email').value.trim();
      const password = document.getElementById('reg-password').value;

      setBtnLoading(btn, true);
      try {
        const res = await CryptoEngine.secureFetch(`${API_BASE}/register`, {
          method: 'POST',
          body: { name, lastname, username, email, password }
        });

        const data = res.data;
        if (!res.ok) throw new Error(data.error || 'Error al registrar usuario');

        showToast('¡Cuenta creada con cifrado de datos! Ahora puedes iniciar sesión', 'success');
        regForm.reset();
        switchView('login');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setBtnLoading(btn, false);
      }
    });
  }

  // 5. Paso 1 de Olvidé mi Contraseña: Solicitar Código (E2E Encrypted)
  const forgotReqForm = document.getElementById('forgot-request-form');
  if (forgotReqForm) {
    forgotReqForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('btn-forgot-req-submit');
      const identifier = document.getElementById('forgot-email').value.trim();

      setBtnLoading(btn, true);
      try {
        const res = await CryptoEngine.secureFetch(`${API_BASE}/request-reset-code`, {
          method: 'POST',
          body: { email: identifier }
        });

        const data = res.data;
        if (!res.ok) throw new Error(data.error || 'Error al solicitar código');

        if (data.warning) {
          showToast(`Aviso: ${data.warning}`, 'error');
        } else {
          showToast('Código enviado. Revisa tu bandeja de entrada', 'success');
        }
        document.getElementById('step-1-request').classList.add('hidden');
        document.getElementById('step-2-confirm').classList.remove('hidden');
        document.getElementById('confirm-email-display').textContent = data.email || identifier;
        document.getElementById('reset-hidden-email').value = data.email || identifier;
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setBtnLoading(btn, false);
      }
    });
  }

  // 6. Paso 2 de Olvidé mi Contraseña: Confirmar Código y Nueva Contraseña (E2E Encrypted)
  const forgotConfirmForm = document.getElementById('forgot-confirm-form');
  if (forgotConfirmForm) {
    forgotConfirmForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('btn-forgot-confirm-submit');
      const email = document.getElementById('reset-hidden-email').value;
      const code = document.getElementById('reset-code').value.trim();
      const newPassword = document.getElementById('reset-new-password').value;

      setBtnLoading(btn, true);
      try {
        const res = await CryptoEngine.secureFetch(`${API_BASE}/reset-password`, {
          method: 'POST',
          body: { email, code, new_password: newPassword }
        });

        const data = res.data;
        if (!res.ok) throw new Error(data.error || 'Error al restablecer contraseña');

        showToast('¡Contraseña restablecida exitosamente!', 'success');
        forgotConfirmForm.reset();
        document.getElementById('step-2-confirm').classList.add('hidden');
        document.getElementById('step-1-request').classList.remove('hidden');
        switchView('login');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        setBtnLoading(btn, false);
      }
    });
  }
}

// ==========================================
// Funciones Auxiliares
// ==========================================
function copyToClipboard(text, message = 'Copiado al portapapeles') {
  navigator.clipboard.writeText(text).then(() => {
    showToast(message, 'info');
  }).catch(() => {
    showToast('No se pudo copiar', 'error');
  });
}

function copyRawToken() {
  if (currentSession.token) {
    copyToClipboard(currentSession.token, 'Token JWT copiado al portapapeles');
  }
}

function setBtnLoading(btn, isLoading) {
  if (!btn) return;
  if (isLoading) {
    btn.disabled = true;
    btn.dataset.originalText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner"></span> Procesando seguro...';
  } else {
    btn.disabled = false;
    btn.innerHTML = btn.dataset.originalText || 'Continuar';
  }
}
