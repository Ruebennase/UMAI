/**
 * UMAI 0.1 — Reusable Browser HTTP Spool Adapter (js/umai-spool.js)
 * Zero-dependency browser/Node client implementing the 5-method UMAI storage contract
 * against the standard HTTP endpoints exposed by pkg/umaispool.Handler.
 */
(function (root, factory) {
  const exportsObj = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = exportsObj;
  }
  root.UMAI = root.UMAI || {};
  root.UMAI.createHttpSpoolAdapter = exportsObj.createHttpSpoolAdapter;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function stripTrailingSlashes(str) {
    let end = str.length;
    while (end > 1 && str.charCodeAt(end - 1) === 47 /* '/' */) {
      end--;
    }
    return str.slice(0, end);
  }

  function invokeHookSafely(hook, args) {
    if (typeof hook !== 'function') return Promise.resolve();
    try {
      return Promise.resolve(hook.apply(null, args)).catch(function () {});
    } catch (_) {
      return Promise.resolve();
    }
  }

  /**
   * Creates a 5-method UMAI storage adapter backed by a pkg/umaispool HTTP endpoint set.
   *
   * @param {Object} [options]
   * @param {string} [options.baseUrl='/api'] Base path prefix where spool routes are mounted
   * @param {Function} [options.fetchImpl] Custom fetch implementation (defaults to global fetch)
   * @param {RequestCredentials} [options.credentials='include'] Fetch credentials mode
   * @param {string} [options.csrfHeaderName='X-UMAI-CSRF'] Header added to state-changing requests
   * @param {string} [options.csrfHeaderValue='1'] Value for csrfHeaderName
   * @param {Object|Function} [options.headers] Static header map or () => Object of extra headers
   * @param {Function} [options.onUnauthorized] Optional callback invoked on HTTP 401 responses
   * @param {Function} [options.onAccepted] Optional UI callback invoked after durable inbox commit
   * @param {Function} [options.onAcknowledged] Optional UI callback invoked after outbox ack cleanup
   */
  function createHttpSpoolAdapter(options) {
    const opts = options || {};
    const rawBase = typeof opts.baseUrl === 'string' && opts.baseUrl.trim() !== ''
      ? opts.baseUrl.trim()
      : '/api';
    const baseUrl = stripTrailingSlashes(rawBase);

    const fetchFn = typeof opts.fetchImpl === 'function'
      ? opts.fetchImpl
      : (typeof fetch === 'function' ? fetch.bind(globalThis) : null);
    if (!fetchFn) {
      throw new Error('UMAI createHttpSpoolAdapter requires global fetch or options.fetchImpl');
    }

    const credentials = opts.credentials !== undefined ? opts.credentials : 'include';
    const csrfHeaderName = opts.csrfHeaderName !== undefined ? opts.csrfHeaderName : 'X-UMAI-CSRF';
    const csrfHeaderValue = opts.csrfHeaderValue !== undefined ? opts.csrfHeaderValue : '1';

    function buildHeaders(extra, isMutating) {
      const merged = {};
      const custom = typeof opts.headers === 'function' ? opts.headers() : opts.headers;
      if (custom && typeof custom === 'object') {
        for (const k of Object.keys(custom)) {
          if (custom[k] !== undefined && custom[k] !== null) {
            merged[k] = String(custom[k]);
          }
        }
      }
      if (isMutating && csrfHeaderName) {
        merged[csrfHeaderName] = String(csrfHeaderValue);
      }
      if (extra && typeof extra === 'object') {
        for (const k of Object.keys(extra)) {
          merged[k] = extra[k];
        }
      }
      return merged;
    }

    async function request(path, init, isMutating) {
      const reqInit = Object.assign({}, init || {});
      reqInit.credentials = credentials;
      reqInit.headers = buildHeaders(reqInit.headers, Boolean(isMutating));
      const res = await fetchFn(baseUrl + path, reqInit);
      if (res.status === 401) {
        await invokeHookSafely(opts.onUnauthorized, [res]);
        const err = new Error('Unauthorized (401)');
        err.status = 401;
        throw err;
      }
      return res;
    }

    return {
      async getOutboxIds() {
        const res = await request('/outbox', { method: 'GET' }, false);
        if (!res.ok) {
          throw new Error('Failed to list outbox messages (' + res.status + ')');
        }
        const data = await res.json();
        const list = Array.isArray(data)
          ? data
          : (data && Array.isArray(data.messages) ? data.messages : null);
        if (!list) {
          throw new Error('Malformed outbox listing response');
        }
        const ids = [];
        for (const item of list) {
          if (typeof item === 'string') {
            ids.push(item);
          } else if (item && typeof item.id === 'string') {
            ids.push(item.id);
          } else {
            throw new Error('Malformed message entry in outbox listing');
          }
        }
        return ids;
      },

      async getMessage(id) {
        if (typeof id !== 'string' || id.length === 0) {
          throw new Error('Invalid message ID for getMessage');
        }
        const encodedId = encodeURIComponent(id);
        const res = await request('/outbox/' + encodedId, { method: 'GET' }, false);
        if (res.status === 404) {
          return null;
        }
        if (!res.ok) {
          throw new Error('Failed to fetch outbox message ' + id + ' (' + res.status + ')');
        }

        const data = await res.json();
        const meta = (data && typeof data === 'object' && data.message && typeof data.message === 'object')
          ? data.message
          : data;
        if (!meta || typeof meta !== 'object' || meta.id !== id) {
          throw new Error('Malformed or mismatched outbox metadata for ' + id);
        }
        if (meta.attachments !== undefined && meta.attachments !== null && !Array.isArray(meta.attachments)) {
          throw new Error('Malformed attachments list in outbox metadata for ' + id);
        }

        const declaredAttachments = meta.attachments || [];
        const files = [];
        for (const att of declaredAttachments) {
          if (!att || typeof att !== 'object') {
            throw new Error('Malformed attachment descriptor in outbox metadata for ' + id);
          }
          const filename = typeof att.name === 'string' && att.name.length > 0
            ? att.name
            : (typeof att.filename === 'string' && att.filename.length > 0 ? att.filename : '');
          if (!filename) {
            throw new Error('Attachment descriptor missing filename for ' + id);
          }

          const fileRes = await request(
            '/outbox/' + encodedId + '/attachments/' + encodeURIComponent(filename),
            { method: 'GET' },
            false
          );
          if (!fileRes.ok) {
            throw new Error(
              'Attachment download failed for ' + filename + ' in message ' + id + ' (' + fileRes.status + ')'
            );
          }

          const blob = await fileRes.blob();
          if (typeof att.size === 'number' && Number.isFinite(att.size) && blob.size !== att.size) {
            throw new Error(
              'Attachment size mismatch for ' + filename + ' in message ' + id +
              ' (expected ' + att.size + ', got ' + blob.size + ')'
            );
          }

          files.push(new File([blob], filename));
        }

        return {
          id: meta.id,
          payload: (meta.payload !== undefined && meta.payload !== null) ? meta.payload : {},
          attachments: files,
          signature: typeof meta.signature === 'string' ? meta.signature : ''
        };
      },

      async getAcceptance(ids) {
        const res = await request(
          '/inbox/acceptance',
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: ids })
          },
          true
        );
        if (!res.ok) {
          throw new Error('Failed to query message acceptance (' + res.status + ')');
        }
        const data = await res.json();
        if (!data || typeof data.results !== 'object' || data.results === null || Array.isArray(data.results)) {
          throw new Error('Malformed acceptance lookup response');
        }

        const normalized = Object.create(null);
        for (const key of Object.keys(data.results)) {
          const entry = data.results[key];
          if (!entry || typeof entry !== 'object' || typeof entry.accepted !== 'boolean') {
            throw new Error('Malformed acceptance entry for ' + key);
          }
          const receipt = typeof entry.ackReceipt === 'string'
            ? entry.ackReceipt
            : (typeof entry.ack_receipt === 'string' ? entry.ack_receipt : '');
          normalized[key] = receipt
            ? { accepted: entry.accepted, ackReceipt: receipt }
            : { accepted: entry.accepted };
        }
        return normalized;
      },

      async acceptMessage(putMsg) {
        const formData = new FormData();
        formData.append('id', putMsg.id);
        const safePayload = (putMsg.payload !== undefined && putMsg.payload !== null)
          ? putMsg.payload
          : {};
        formData.append('payload', JSON.stringify(safePayload));
        if (putMsg.signature) {
          formData.append('signature', putMsg.signature);
        }

        for (const file of (putMsg.attachments || [])) {
          formData.append('attachments', file, file.name);
        }

        const res = await request(
          '/inbox',
          {
            method: 'POST',
            body: formData
          },
          true
        );
        if (!res.ok) {
          return { accepted: false };
        }

        const data = await res.json();
        if (!data || data.accepted !== true) {
          return { accepted: false };
        }

        const ackReceipt = typeof data.ack_receipt === 'string'
          ? data.ack_receipt
          : (typeof data.ackReceipt === 'string' ? data.ackReceipt : '');

        await invokeHookSafely(opts.onAccepted, [putMsg, data]);

        return {
          accepted: true,
          ackReceipt: ackReceipt
        };
      },

      async onAcknowledged(ids, receipts) {
        const res = await request(
          '/outbox/ack',
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: ids, receipts: receipts || {} })
          },
          true
        );
        if (!res.ok) {
          throw new Error('Failed to acknowledge outbox messages on server (' + res.status + ')');
        }
        await invokeHookSafely(opts.onAcknowledged, [ids, receipts || {}]);
      }
    };
  }

  return {
    createHttpSpoolAdapter: createHttpSpoolAdapter
  };
});
