// Application A — Background Sync Worker Controller
(function () {
  'use strict';

  const activeContainer = document.getElementById('sync-active-container');
  const authContainer = document.getElementById('sync-auth-container');
  const syncDot = document.getElementById('sync-dot');
  const syncDetail = document.getElementById('sync-detail');
  const loginForm = document.getElementById('sync-login-form');
  const loginError = document.getElementById('sync-login-error');
  const btnPopupAuth = document.getElementById('btn-popup-auth');

  let peerOrigin = '';
  let umaiSession = null;
  let isAuthenticated = false;

  function notifyParent(type, payload = {}) {
    if (window.parent && window.parent !== window && peerOrigin) {
      window.parent.postMessage({
        protocol: 'UMAI_CONTROL',
        source: 'app-a',
        type: type,
        ...payload
      }, peerOrigin);
    }
  }

  async function api(path, options = {}) {
    options.credentials = 'include';
    options.headers = options.headers || {};
    options.headers['X-UMAI-CSRF'] = '1';
    const res = await fetch(path, options);
    if (res.status === 401) {
      showAuthRequired();
      throw new Error('Unauthorized');
    }
    return res;
  }

  async function init() {
    try {
      const statusRes = await fetch('/api/status', { credentials: 'include' });
      const status = await statusRes.json();
      peerOrigin = status.peer_origin || status.peerOrigin || 'http://127.0.0.1:8082';

      if (window.location.hostname === 'localhost') {
        peerOrigin = peerOrigin.replace('127.0.0.1', 'localhost');
      } else if (window.location.hostname === '127.0.0.1') {
        peerOrigin = peerOrigin.replace('localhost', '127.0.0.1');
      }

      const meRes = await api('/api/auth/me');
      if (meRes.ok) {
        const me = await meRes.json();
        if (me.authenticated) {
          startSyncWorker();
          return;
        }
      }
    } catch (e) {
      // 401 or network error falls through to showAuthRequired
    }
    showAuthRequired();
  }

  function showAuthRequired() {
    isAuthenticated = false;
    if (umaiSession) {
      umaiSession.stop();
      umaiSession = null;
    }
    activeContainer.style.display = 'none';
    authContainer.style.display = 'block';
    notifyParent('AUTH_REQUIRED');
  }

  function startSyncWorker() {
    isAuthenticated = true;
    authContainer.style.display = 'none';
    activeContainer.style.display = 'block';
    notifyParent('AUTH_OK');

    const storageAdapter = {
      async getOutboxIds() {
        const res = await api('/api/outbox');
        if (!res.ok) return [];
        const data = await res.json();
        const list = Array.isArray(data) ? data : (data.messages || []);
        return list.map(m => m.id);
      },

      async getMessage(id) {
        const res = await api(`/api/outbox/${encodeURIComponent(id)}`);
        if (!res.ok) return null;
        const data = await res.json();
        const meta = data.message || data;
        if (!meta || !meta.id) return null;

        const files = [];
        for (const att of (meta.attachments || [])) {
          const filename = att.name || att.filename;
          const fileRes = await api(
            `/api/outbox/${encodeURIComponent(id)}/attachments/${encodeURIComponent(filename)}`
          );
          if (fileRes.ok) {
            const blob = await fileRes.blob();
            files.push(new File([blob], filename, { type: blob.type }));
          }
        }

        return {
          id: meta.id,
          payload: (meta.payload !== undefined && meta.payload !== null) ? meta.payload : {},
          attachments: files,
          signature: meta.signature || ''
        };
      },

      async isAccepted(id) {
        const res = await api('/api/accepted/receipts');
        if (!res.ok) return { accepted: false };
        const receiptsMap = await res.json();
        if (receiptsMap && Object.prototype.hasOwnProperty.call(receiptsMap, id)) {
          return { accepted: true, ackReceipt: receiptsMap[id] || '' };
        }
        return { accepted: false };
      },

      async acceptMessage(msg) {
        const formData = new FormData();
        formData.append('id', msg.id);
        const safePayload = (msg.payload !== undefined && msg.payload !== null) ? msg.payload : {};
        formData.append('payload', JSON.stringify(safePayload));
        if (msg.signature) {
          formData.append('signature', msg.signature);
        }
        for (const f of msg.attachments || []) {
          formData.append('attachments', f, f.name);
        }
        const res = await api('/api/inbox', {
          method: 'POST',
          body: formData
        });
        if (!res.ok) return { accepted: false };
        const data = await res.json();
        return { accepted: true, ackReceipt: data.ack_receipt || '' };
      },

      async onAcknowledged(ids, receipts) {
        const res = await api('/api/outbox/ack', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ids: ids, receipts: receipts || {} })
        });
        if (!res.ok) {
          throw new Error('Failed to acknowledge outbox messages on server');
        }
      }
    };

    if (umaiSession) {
      umaiSession.stop();
    }

    umaiSession = new UMAI.UmaiSession({
      peerOrigin: peerOrigin,
      role: 'embedded',
      storage: storageAdapter,
      onSyncStatus: function (status) {
        if (status.isSyncing) {
          syncDot.className = 'pulse-dot syncing';
          syncDetail.textContent = status.detail || 'Transferring...';
        } else {
          syncDot.className = 'pulse-dot';
          syncDetail.textContent = 'In sync';
        }
        notifyParent('SYNC_STATUS', { status: status });
      },
      onStatusChange: function ({ state }) {
        notifyParent('STATUS_CHANGE', { state: state });
      }
    });

    umaiSession.start();
  }

  loginForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    loginError.style.display = 'none';

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-UMAI-CSRF': '1' },
        credentials: 'include',
        body: JSON.stringify({
          username: document.getElementById('sync-username').value.trim(),
          password: document.getElementById('sync-password').value
        })
      });

      const data = await res.json();
      if (res.ok && data.authenticated) {
        try {
          localStorage.setItem('umai_auth_event_a', 'login:' + Date.now());
        } catch (e) {}
        startSyncWorker();
      } else {
        loginError.textContent = data.error || 'Authentication failed';
        loginError.style.display = 'block';
      }
    } catch (err) {
      loginError.textContent = err.message || 'Authentication failed';
      loginError.style.display = 'block';
    }
  });

  // Top-level authentication with ephemeral WebCrypto Proof-of-Possession (ECDSA P-256) session bootstrap.
  // Designed for Federated Identity Providers (OIDC / SAML / eID) that forbid iframe framing (X-Frame-Options: DENY)
  // and browsers where third-party cookies/storage are partitioned across top-level sites.
  function bytesToHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  }

  let activeBootstrapState = null;

  if (btnPopupAuth) {
    btnPopupAuth.addEventListener('click', async function () {
      loginError.style.display = 'none';
      if (!window.crypto || !window.crypto.subtle) {
        window.open('/', '_blank');
        return;
      }

      try {
        // 1. Generate a non-extractable ephemeral ECDSA P-256 key pair inside the iframe
        const keyPair = await window.crypto.subtle.generateKey(
          { name: 'ECDSA', namedCurve: 'P-256' },
          false,
          ['sign', 'verify']
        );
        const rawPub = new Uint8Array(await window.crypto.subtle.exportKey('raw', keyPair.publicKey));
        const pubHex = bytesToHex(rawPub);

        // 2. Register pending bootstrap transaction with App A's backend
        const initRes = await fetch('/api/auth/bootstrap/init', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-UMAI-CSRF': '1' },
          credentials: 'include',
          body: JSON.stringify({ public_key: pubHex })
        });
        if (!initRes.ok) {
          throw new Error('Failed to initialize auth bootstrap transaction');
        }
        const tx = await initRes.json();

        // 3. Open top-level authentication window on App A bound to tx_id and opener_nonce.
        // Upon user authorization, the popup delivers a one-time auth_secret directly to this iframe
        // via same-origin window.opener.postMessage, which we then sign with our non-extractable P-256 key.
        const popupUrl = `/?auth_tx=${encodeURIComponent(tx.tx_id)}&opener_nonce=${encodeURIComponent(tx.opener_nonce)}`;
        const popupWin = window.open(popupUrl, 'umai_top_level_auth', 'popup,width=520,height=640');
        activeBootstrapState = {
          txId: tx.tx_id,
          challenge: tx.challenge,
          privateKey: keyPair.privateKey,
          popupWin: popupWin
        };
      } catch (err) {
        loginError.textContent = err.message || 'Top-level bootstrap failed';
        loginError.style.display = 'block';
      }
    });
  }

  // Listen for same-origin popup bootstrap grant and parent control messages
  window.addEventListener('message', async function (e) {
    if (
      activeBootstrapState &&
      e.origin === window.location.origin &&
      e.source === activeBootstrapState.popupWin &&
      e.data &&
      e.data.protocol === 'UMAI_BOOTSTRAP' &&
      e.data.type === 'UMAI_BOOTSTRAP_GRANT' &&
      e.data.tx_id === activeBootstrapState.txId &&
      typeof e.data.auth_secret === 'string' &&
      e.data.auth_secret.length > 0
    ) {
      const state = activeBootstrapState;
      activeBootstrapState = null;
      try {
        const challengeBytes = new TextEncoder().encode(
          `UMAI-BOOTSTRAP-V1:${state.txId}:${state.challenge}:${e.data.auth_secret}`
        );
        const sigBuf = await window.crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          state.privateKey,
          challengeBytes
        );
        const sigHex = bytesToHex(new Uint8Array(sigBuf));
        const redeemRes = await fetch('/api/auth/bootstrap/redeem', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-UMAI-CSRF': '1' },
          credentials: 'include',
          body: JSON.stringify({
            tx_id: state.txId,
            auth_secret: e.data.auth_secret,
            signature: sigHex
          })
        });
        if (redeemRes.ok) {
          startSyncWorker();
        }
      } catch (err) {
        loginError.textContent = err.message || 'Failed to redeem bootstrap session';
        loginError.style.display = 'block';
      }
      return;
    }

    if (peerOrigin && e.origin !== peerOrigin) return;
    if (window.parent && e.source !== window.parent) return;
    if (!e.data || e.data.protocol !== 'UMAI_CONTROL') return;
    if (e.data.type === 'TRIGGER_SYNC') {
      if (umaiSession && isAuthenticated) {
        umaiSession.reconcile();
      } else {
        init();
      }
    } else if (e.data.type === 'PING_AUTH') {
      notifyParent(isAuthenticated ? 'AUTH_OK' : 'AUTH_REQUIRED');
    }
  });

  // If user logs into or out of App A in a separate tab, re-check HttpOnly cookie session
  window.addEventListener('storage', function (e) {
    if (e.key === 'umai_auth_event_a') {
      init();
    }
  });

  init();
})();
