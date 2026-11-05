// Application B — Frontend Host Controller
(function () {
  'use strict';

  let umaiSession = null;
  let serverConfig = null;

  // DOM Elements
  const authContainer = document.getElementById('auth-container');
  const appContainer = document.getElementById('app-container');
  const loginForm = document.getElementById('login-form');
  const loginError = document.getElementById('login-error');

  const connBadge = document.getElementById('conn-badge');
  const btnSync = document.getElementById('btn-sync');
  const btnLogout = document.getElementById('btn-logout');
  const btnClearLog = document.getElementById('btn-clear-log');
  const bOriginLabel = document.getElementById('b-origin-label');
  const aOriginLabel = document.getElementById('a-origin-label');
  const bStatOutbox = document.getElementById('b-stat-outbox');
  const bStatInbox = document.getElementById('b-stat-inbox');

  const peerIframe = document.getElementById('peer-iframe');
  const btnReloadIframe = document.getElementById('btn-reload-iframe');
  const btnOpenTop = document.getElementById('btn-open-top');

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

  let sessionToken = localStorage.getItem('umai_token_b') || sessionStorage.getItem('umai_token_b') || '';

  // --- API Utilities ---
  async function api(path, options = {}) {
    options.credentials = 'include';
    options.headers = options.headers || {};
    if (sessionToken) {
      if (options.headers instanceof Headers) {
        options.headers.set('X-UMAI-Session', sessionToken);
      } else {
        options.headers['X-UMAI-Session'] = sessionToken;
      }
    }
    const res = await fetch(path, options);
    if (res.status === 401) {
      sessionToken = '';
      localStorage.removeItem('umai_token_b');
      sessionStorage.removeItem('umai_token_b');
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

  // --- Auth Flow ---
  async function checkAuth() {
    try {
      const res = await api('/api/auth/me');
      const data = await res.json();
      if (data.authenticated) {
        if (data.session_id) {
          sessionToken = data.session_id;
          localStorage.setItem('umai_token_b', sessionToken);
          sessionStorage.setItem('umai_token_b', sessionToken);
        }
        showApp();
      } else {
        showAuth();
      }
    } catch (e) {
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

  function showApp() {
    authContainer.style.display = 'none';
    appContainer.style.display = 'flex';
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
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (res.ok && data.authenticated) {
        sessionToken = data.session_id || '';
        localStorage.setItem('umai_token_b', sessionToken);
        sessionStorage.setItem('umai_token_b', sessionToken);
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
      sessionToken = '';
      localStorage.removeItem('umai_token_b');
      sessionStorage.removeItem('umai_token_b');
      showAuth();
    }
  });

  btnClearLog.addEventListener('click', () => {
    logBox.innerHTML = '';
  });

  // --- Iframe controls ---
  btnReloadIframe.addEventListener('click', () => {
    if (peerIframe && serverConfig) {
      peerIframe.src = serverConfig.peer_embed_url || serverConfig.peer_origin;
      appendLog('info', 'Reloading embedded Application A iframe');
      if (umaiSession) {
        umaiSession.stop();
        setTimeout(() => {
          initUmaiSession(serverConfig.peer_origin);
        }, 500);
      }
    }
  });

  // --- Initialization ---
  async function initApp() {
    try {
      const statusRes = await api('/api/status');
      serverConfig = await statusRes.json();

      bOriginLabel.textContent = serverConfig.listen_addr;
      aOriginLabel.textContent = serverConfig.peer_origin;

      btnOpenTop.href = serverConfig.peer_origin;

      await loadDocuments();
      await loadOutbox();
      await loadInbox();

      // Periodically refresh lists so standalone tabs show incoming files in real-time
      if (!window._refreshTimer) {
        window._refreshTimer = setInterval(async () => {
          if (sessionToken) {
            await loadDocuments();
            await loadOutbox();
            await loadInbox();
          }
        }, 2000);
      }

      // Load App A in iframe
      let embedUrl = serverConfig.peer_embed_url || serverConfig.peer_origin;
      let peerOrigin = serverConfig.peer_origin;

      if (window.location.hostname === 'localhost') {
        embedUrl = embedUrl.replace('127.0.0.1', 'localhost');
        peerOrigin = peerOrigin.replace('127.0.0.1', 'localhost');
      } else if (window.location.hostname === '127.0.0.1') {
        embedUrl = embedUrl.replace('localhost', '127.0.0.1');
        peerOrigin = peerOrigin.replace('localhost', '127.0.0.1');
      }

      if (peerIframe.src !== embedUrl) {
        peerIframe.src = embedUrl;
      }

      initUmaiSession(peerOrigin);
    } catch (err) {
      appendLog('error', 'Initialization error:', err.message);
    }
  }

  // --- Document Operations ---
  async function loadDocuments() {
    try {
      const res = await api('/api/docs');
      const docs = await res.json();
      docsCount.textContent = docs.length;

      docsList.innerHTML = '';
      attachDocsContainer.innerHTML = '';

      if (docs.length === 0) {
        docsList.innerHTML = '<li class="empty-state">No local documents yet.</li>';
        attachDocsContainer.innerHTML = '<span class="empty-state">Upload documents to attach.</span>';
        return;
      }

      docs.forEach((doc) => {
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

        const label = document.createElement('label');
        label.style.display = 'block';
        label.style.marginBottom = '2px';
        label.innerHTML = `
          <input type="checkbox" name="attach_doc" value="${escapeHtml(doc.name)}">
          ${escapeHtml(doc.name)} (${formatBytes(doc.size)})
        `;
        attachDocsContainer.appendChild(label);
      });

      document.querySelectorAll('.btn-delete-doc').forEach((btn) => {
        btn.addEventListener('click', async (e) => {
          const docName = e.target.dataset.name;
          if (confirm(`Delete document "${docName}"?`)) {
            await api(`/api/docs/${encodeURIComponent(docName)}`, { method: 'DELETE' });
            loadDocuments();
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
        await loadDocuments();
      }
    } catch (err) {
      appendLog('error', 'Upload failed', err.message);
    }
  });

  // --- Outbox & Inbox ---
  async function loadOutbox() {
    try {
      const res = await api('/api/outbox');
      const messages = await res.json();
      outboxCount.textContent = messages.length;
      bStatOutbox.textContent = `Outbox: ${messages.length}`;

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
      bStatInbox.textContent = `Inbox: ${messages.length}`;

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

  // --- Storage Adapter ---
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
          attachments: files
        };
      },

      async isAccepted(id) {
        const res = await api('/api/accepted');
        const acceptedList = await res.json();
        return Array.isArray(acceptedList) && acceptedList.includes(id);
      },

      async acceptMessage(putMsg) {
        const formData = new FormData();
        formData.append('id', putMsg.id);
        formData.append('payload', JSON.stringify(putMsg.payload || {}));

        for (const file of putMsg.attachments || []) {
          formData.append('attachments', file, file.name);
        }

        const res = await api('/api/inbox', {
          method: 'POST',
          body: formData
        });

        if (res.ok) {
          await loadInbox();
          return true;
        }
        return false;
      },

      async onAcknowledged(ids) {
        await api('/api/outbox/ack', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ids })
        });
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
      role: 'host',
      iframe: peerIframe,
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

    // When iframe fires load event, host initiates handshake
    if (!peerIframe._loadBound) {
      peerIframe._loadBound = true;
      peerIframe.addEventListener('load', () => {
        if (peerIframe.src && peerIframe.src !== 'about:blank') {
          appendLog('info', 'Iframe load event detected; starting UMAI session');
          if (umaiSession) umaiSession.start();
        }
      });
    }

    umaiSession.start();
  }

  btnSync.addEventListener('click', () => {
    if (umaiSession) {
      appendLog('info', 'Manual synchronization requested');
      umaiSession.reconcile(true);
    }
  });

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
      .replace(/"/g, '&quot;');
  }

  // Start
  checkAuth();
})();
