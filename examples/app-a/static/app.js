// Application A — Frontend Controller
(function () {
  'use strict';

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.getRegistrations().then(function (regs) {
      for (const r of regs) r.unregister();
    });
  }

  let umaiSession = null;
  let serverConfig = null;

  // DOM Elements
  const authContainer = document.getElementById('auth-container');
  const appContainer = document.getElementById('app-container');
  const loginForm = document.getElementById('login-form');
  const loginError = document.getElementById('login-error');
  const iframeCookieNotice = document.getElementById('iframe-cookie-notice');

  const appTitle = document.getElementById('app-title');
  const connBadge = document.getElementById('conn-badge');
  const btnSync = document.getElementById('btn-sync');
  const btnLogout = document.getElementById('btn-logout');
  const btnClearLog = document.getElementById('btn-clear-log');

  const docsList = document.getElementById('docs-list');
  const docsCount = document.getElementById('docs-count');
  const uploadDocForm = document.getElementById('upload-doc-form');
  const fileInput = document.getElementById('file-input');

  const createMsgForm = document.getElementById('create-msg-form');
  const msgSubject = document.getElementById('msg-subject');
  const msgText = document.getElementById('msg-text');
  const attachDocsContainer = document.getElementById('attach-docs-container');

  const outboxList = document.getElementById('outbox-list');
  const outboxCount = document.getElementById('outbox-count');
  const inboxList = document.getElementById('inbox-list');
  const inboxCount = document.getElementById('inbox-count');
  const logBox = document.getElementById('log-box');

  // Check if embedded in iframe
  const isEmbedded = window.parent !== window;
  if (isEmbedded && iframeCookieNotice) {
    iframeCookieNotice.style.display = 'block';
  }

  let isAuthenticated = false;

  // --- API Utilities ---
  async function api(path, options = {}) {
    options.credentials = 'include';
    options.headers = options.headers || {};
    if (options.headers instanceof Headers) {
      options.headers.set('X-UMAI-CSRF', '1');
    } else {
      options.headers['X-UMAI-CSRF'] = '1';
    }
    const res = await fetch(path, options);
    if (res.status === 401) {
      isAuthenticated = false;
      showAuth();
      throw new Error('Unauthorized');
    }
    return res;
  }

  function appendLog(level, message, details) {
    if (!logBox) return;
    const time = new Date().toLocaleTimeString();
    const entry = document.createElement('div');
    entry.className = `log-entry ${level}`;
    let text = `[${time}] ${message}`;
    if (details) {
      text += ` ${typeof details === 'object' ? JSON.stringify(details) : details}`;
    }
    entry.textContent = text;
    logBox.appendChild(entry);
    logBox.scrollTop = logBox.scrollHeight;
  }

  // --- Authentication Flow ---
  async function checkAuth() {
    try {
      const res = await api('/api/auth/me');
      const data = await res.json();
      if (data.authenticated) {
        isAuthenticated = true;
        showApp();
      } else {
        isAuthenticated = false;
        showAuth();
      }
    } catch (e) {
      isAuthenticated = false;
      showAuth();
    }
  }

  function showAuth() {
    if (umaiSession) {
      umaiSession.stop();
      umaiSession = null;
    }
    authContainer.style.display = 'block';
    appContainer.style.display = 'none';
  }

  async function completePendingBootstrapIfPresent() {
    const params = new URLSearchParams(window.location.search);
    const txId = params.get('auth_tx');
    const openerNonce = params.get('opener_nonce');
    if (!txId || !openerNonce) return false;

    // Security (D1): Require a live in-browser window.opener relationship and explicit user confirmation
    // before authorizing a pending iframe bootstrap transaction, and deliver the resulting one-time
    // auth_secret exclusively via same-origin postMessage to window.opener (never via URL).
    if (!window.opener || window.opener === window) {
      window.history.replaceState({}, document.title, window.location.pathname);
      return false;
    }

    if (typeof window.confirm === 'function') {
      const approved = window.confirm('Authorize the embedded UMAI synchronization frame to connect to your session?');
      if (!approved) {
        window.history.replaceState({}, document.title, window.location.pathname);
        return false;
      }
    }

    try {
      const res = await api('/api/auth/bootstrap/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tx_id: txId, opener_nonce: openerNonce })
      });
      if (res.ok) {
        const data = await res.json();
        window.history.replaceState({}, document.title, window.location.pathname);
        if (window.opener && data.auth_secret) {
          window.opener.postMessage({
            protocol: 'UMAI_BOOTSTRAP',
            type: 'UMAI_BOOTSTRAP_GRANT',
            tx_id: txId,
            auth_secret: data.auth_secret
          }, window.location.origin);
          window.close();
          return true;
        }
      }
    } catch (e) {
      // ignore bootstrap error and continue to normal app view
    }
    return false;
  }

  async function showApp() {
    if (await completePendingBootstrapIfPresent()) {
      return;
    }
    authContainer.style.display = 'none';
    appContainer.style.display = 'block';
    initApp();
  }

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginError.style.display = 'none';
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-UMAI-CSRF': '1' },
        credentials: 'include',
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (res.ok && data.authenticated) {
        isAuthenticated = true;
        try {
          localStorage.setItem('umai_auth_event_a', 'login:' + Date.now());
        } catch (e) {}
        showApp();
      } else {
        loginError.textContent = data.error || 'Login failed';
        loginError.style.display = 'block';
      }
    } catch (err) {
      loginError.textContent = 'Network or server error';
      loginError.style.display = 'block';
    }
  });

  btnLogout.addEventListener('click', async () => {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } finally {
      isAuthenticated = false;
      try {
        localStorage.setItem('umai_auth_event_a', 'logout:' + Date.now());
      } catch (e) {}
      showAuth();
    }
  });

  btnClearLog.addEventListener('click', () => {
    logBox.innerHTML = '';
  });

  // --- App Initialization & Data Loading ---
  async function initApp() {
    try {
      const statusRes = await api('/api/status');
      serverConfig = await statusRes.json();

      appTitle.textContent = serverConfig.app_name || 'Application A';
      await loadDocuments();
      await loadOutbox();
      await loadInbox();

      // Periodically refresh lists so standalone tabs show incoming files in real-time
      if (!window._refreshTimer) {
        window._refreshTimer = setInterval(async () => {
          if (isAuthenticated) {
            await loadDocuments();
            await loadOutbox();
            await loadInbox();
          }
        }, 2000);
      }

      initUmaiSession(serverConfig.peer_origin);
    } catch (err) {
      appendLog('error', 'Initialization error:', err.message);
    }
  }

  // --- Document Operations ---
  let _lastDocsSignature = null;

  async function loadDocuments(forceRender = false) {
    try {
      const res = await api('/api/docs');
      const docs = await res.json();
      const sig = JSON.stringify(docs.map(d => `${d.name}:${d.size}:${d.mod_time}`));
      if (!forceRender && sig === _lastDocsSignature) {
        return;
      }
      _lastDocsSignature = sig;

      // Preserve currently checked attachments across re-renders
      const selectedDocs = new Set(
        Array.from(document.querySelectorAll('input[name="attach_doc"]:checked')).map(el => el.value)
      );

      docsCount.textContent = docs.length;

      docsList.innerHTML = '';
      attachDocsContainer.innerHTML = '';

      if (docs.length === 0) {
        docsList.innerHTML = '<li class="empty-state">No local documents yet.</li>';
        attachDocsContainer.innerHTML = '<span class="empty-state">Upload documents above to attach them.</span>';
        return;
      }

      docs.forEach((doc) => {
        // Document list item
        const li = document.createElement('li');
        li.className = 'list-item';
        li.innerHTML = `
          <div>
            <div class="list-item-title">${escapeHtml(doc.name)}</div>
            <div class="list-item-sub">${formatBytes(doc.size)} • ${new Date(doc.mod_time).toLocaleTimeString()}</div>
          </div>
          <div style="display: flex; gap: 4px;">
            <a href="/api/docs/${encodeURIComponent(doc.name)}" class="btn btn-secondary btn-sm" download>Download</a>
            <button class="btn btn-danger btn-sm btn-delete-doc" data-name="${escapeHtml(doc.name)}">Delete</button>
          </div>
        `;
        docsList.appendChild(li);

        // Attachment checkbox item
        const label = document.createElement('label');
        label.style.display = 'block';
        label.style.marginBottom = '3px';
        const isChecked = selectedDocs.has(doc.name) ? 'checked' : '';
        label.innerHTML = `
          <input type="checkbox" name="attach_doc" value="${escapeHtml(doc.name)}" ${isChecked}>
          ${escapeHtml(doc.name)} (${formatBytes(doc.size)})
        `;
        attachDocsContainer.appendChild(label);
      });

      // Hook delete buttons
      document.querySelectorAll('.btn-delete-doc').forEach((btn) => {
        btn.addEventListener('click', async (e) => {
          const docName = e.target.dataset.name;
          if (confirm(`Delete document "${docName}"?`)) {
            await api(`/api/docs/${encodeURIComponent(docName)}`, { method: 'DELETE' });
            loadDocuments(true);
          }
        });
      });
    } catch (err) {
      appendLog('error', 'Failed loading documents', err.message);
    }
  }

  uploadDocForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!fileInput.files.length) return;

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    try {
      const res = await api('/api/docs', { method: 'POST', body: formData });
      if (res.ok) {
        fileInput.value = '';
        appendLog('info', 'Uploaded document successfully');
        await loadDocuments(true);
      }
    } catch (err) {
      appendLog('error', 'Upload failed', err.message);
    }
  });

  // --- Outbox & Inbox Loading ---
  async function loadOutbox() {
    try {
      const res = await api('/api/outbox');
      const messages = await res.json();
      outboxCount.textContent = messages.length;

      outboxList.innerHTML = '';
      if (messages.length === 0) {
        outboxList.innerHTML = '<li class="empty-state">Outbox empty.</li>';
        return;
      }

      messages.forEach((msg) => {
        const li = document.createElement('li');
        li.className = 'list-item';
        const subj = msg.payload?.subject || 'No subject';
        const attCount = msg.attachments ? msg.attachments.length : 0;
        li.innerHTML = `
          <div>
            <div class="list-item-title">${escapeHtml(msg.id)}: ${escapeHtml(subj)}</div>
            <div class="list-item-sub">
              ${attCount} attachment(s) • Created ${new Date(msg.created_at).toLocaleTimeString()}
            </div>
            <div>
              ${(msg.attachments || []).map(a => `<span class="attachment-badge">${escapeHtml(a.name)} (${formatBytes(a.size)})</span>`).join('')}
            </div>
          </div>
          <span class="badge badge-handshaking" style="font-size: 11px;">Pending</span>
        `;
        outboxList.appendChild(li);
      });
    } catch (err) {
      appendLog('error', 'Failed loading outbox', err.message);
    }
  }

  async function loadInbox() {
    try {
      const res = await api('/api/inbox');
      const messages = await res.json();
      inboxCount.textContent = messages.length;

      inboxList.innerHTML = '';
      if (messages.length === 0) {
        inboxList.innerHTML = '<li class="empty-state">No messages received yet.</li>';
        return;
      }

      messages.forEach((msg) => {
        const li = document.createElement('li');
        li.className = 'list-item';
        const subj = msg.payload?.subject || 'No subject';
        const note = msg.payload?.text || '';
        li.innerHTML = `
          <div style="flex: 1;">
            <div class="list-item-title">${escapeHtml(msg.id)}: ${escapeHtml(subj)}</div>
            <div class="list-item-sub">Received ${new Date(msg.created_at).toLocaleTimeString()} ${note ? `• "${escapeHtml(note)}"` : ''}</div>
            <div style="margin-top: 4px;">
              ${(msg.attachments || []).map(a => `
                <a href="/api/inbox/${encodeURIComponent(msg.id)}/attachments/${encodeURIComponent(a.name)}"
                   class="attachment-badge" download style="color: var(--primary); text-decoration: none;">
                  📥 ${escapeHtml(a.name)} (${formatBytes(a.size)})
                </a>
              `).join('')}
            </div>
          </div>
          <span class="badge badge-connected" style="font-size: 11px;">Accepted</span>
        `;
        inboxList.appendChild(li);
      });
    } catch (err) {
      appendLog('error', 'Failed loading inbox', err.message);
    }
  }

  // --- Create Message ---
  createMsgForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const subject = msgSubject.value.trim();
    const text = msgText.value.trim();
    const checked = Array.from(document.querySelectorAll('input[name="attach_doc"]:checked')).map(el => el.value);

    const payload = { subject, text, timestamp: new Date().toISOString() };

    try {
      const res = await api('/api/outbox', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload, documents: checked })
      });
      if (res.ok) {
        const created = await res.json();
        appendLog('info', `Created outbox message: ${created.id}`);
        msgSubject.value = '';
        msgText.value = '';
        document.querySelectorAll('input[name="attach_doc"]').forEach(el => el.checked = false);
        await loadOutbox();

        // Trigger automatic sync
        if (umaiSession) {
          umaiSession.reconcile();
        }
      }
    } catch (err) {
      appendLog('error', 'Failed to create message', err.message);
    }
  });

  // --- UMAI Session Storage Adapter ---
  function createUmaiStorageAdapter() {
    return {
      async getOutboxIds() {
        const res = await api('/api/outbox');
        const list = await res.json();
        return list.map(m => m.id);
      },

      async getMessage(id) {
        const res = await api(`/api/outbox/${encodeURIComponent(id)}`);
        if (!res.ok) return null;
        const meta = await res.json();

        // Fetch attachment binary files as native File objects
        const files = [];
        for (const att of meta.attachments || []) {
          const fileRes = await api(`/api/outbox/${encodeURIComponent(id)}/attachments/${encodeURIComponent(att.name)}`);
          const blob = await fileRes.blob();
          const file = new File([blob], att.name, { type: blob.type, lastModified: Date.now() });
          files.push(file);
        }

        return {
          id: meta.id,
          payload: meta.payload,
          attachments: files,
          signature: meta.signature || ''
        };
      },

      async isAccepted(id) {
        const res = await api('/api/accepted/receipts');
        const receiptsMap = await res.json();
        if (receiptsMap && Object.prototype.hasOwnProperty.call(receiptsMap, id)) {
          return { accepted: true, ackReceipt: receiptsMap[id] || '' };
        }
        return { accepted: false };
      },

      async acceptMessage(putMsg) {
        const formData = new FormData();
        formData.append('id', putMsg.id);
        const safePayload = (putMsg.payload !== undefined && putMsg.payload !== null) ? putMsg.payload : {};
        formData.append('payload', JSON.stringify(safePayload));
        if (putMsg.signature) {
          formData.append('signature', putMsg.signature);
        }

        for (const file of putMsg.attachments || []) {
          formData.append('attachments', file, file.name);
        }

        const res = await api('/api/inbox', {
          method: 'POST',
          body: formData
        });

        if (res.ok) {
          const data = await res.json();
          await loadInbox();
          return { accepted: true, ackReceipt: data.ack_receipt || '' };
        }
        return { accepted: false };
      },

      async onAcknowledged(ids, receipts) {
        const res = await api('/api/outbox/ack', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ids, receipts: receipts || {} })
        });
        if (!res.ok) {
          throw new Error('Failed to acknowledge outbox messages on server');
        }
        await loadOutbox();
      }
    };
  }

  // --- Initialize UMAI Session ---
  function initUmaiSession(peerOrigin) {
    if (umaiSession) {
      umaiSession.stop();
    }

    const storage = createUmaiStorageAdapter();

    umaiSession = new UMAI.UmaiSession({
      peerOrigin: peerOrigin,
      role: isEmbedded ? 'embedded' : 'host',
      storage: storage,
      onStatusChange({ state, detail }) {
        connBadge.className = `badge badge-${state}`;
        connBadge.textContent = state.charAt(0).toUpperCase() + state.slice(1);
      },
      onLog({ level, message, details }) {
        appendLog(level, message, details);
      },
      onError(err) {
        appendLog('error', 'Protocol Error:', err.message);
      },
      onTransfer({ direction, type, id, ids, attachmentCount }) {
        let text = `${direction === 'incoming' ? '📥' : '📤'} ${type}`;
        if (id) text += ` [${id}]`;
        if (ids && ids.length) text += ` [${ids.join(', ')}]`;
        if (attachmentCount !== undefined) text += ` (${attachmentCount} files)`;
        appendLog('info', text);
      }
    });

    umaiSession.start();
  }

  btnSync.addEventListener('click', () => {
    if (umaiSession) {
      appendLog('info', 'Manual synchronization requested');
      umaiSession.reconcile(true);
    }
  });

  // Utilities
  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Start auth check
  window.addEventListener('storage', (e) => {
    if (e.key === 'umai_auth_event_a') {
      checkAuth();
    }
  });
  checkAuth();
})();
