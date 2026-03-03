/**
 * ShivaMarg Comments — comments.js
 * Drop-in comments section for any page.
 * Requires auth.js to be loaded first.
 *
 * Usage in HTML:
 *   <!-- 1. Add a container with a page identifier -->
 *   <div id="sm-comments" data-page-id="shiv-aarti"></div>
 *
 *   <!-- 2. Load scripts -->
 *   <script src="/js/auth.js"></script>
 *   <script src="/js/comments.js"></script>
 *   <script>
 *     SmAuth.init({ apiBase: 'http://localhost:8000' });
 *     SmComments.init({ apiBase: 'http://localhost:8000' });
 *   </script>
 */

(function () {
  'use strict';

  const TOKEN_KEY = 'sm_token';
  let API_BASE    = 'http://localhost:8000';
  const LIMIT     = 15;

  let pageId    = null;
  let comments  = [];
  let total     = 0;
  let skip      = 0;
  let loading   = false;
  let editingId = null;

  /* ─── STYLES ─── */
  function injectStyles() {
    if (document.getElementById('sm-comments-styles')) return;
    const s = document.createElement('style');
    s.id = 'sm-comments-styles';
    s.textContent = `
      /* ── Container ── */
      .sm-comments-wrap {
        max-width: 800px; margin: 0 auto; padding: 0 0 80px;
        font-family: 'EB Garamond', 'Playfair Display', serif;
      }

      /* ── Section heading ── */
      .sm-comments-heading {
        font-family: 'Cinzel', serif;
        font-size: 1.22rem; color: #C9A84C;
        letter-spacing: 3px; margin-bottom: 24px;
        padding-bottom: 12px;
        border-bottom: 1px solid rgba(124,77,255,0.18);
        display: flex; align-items: center; justify-content: space-between;
        flex-wrap: wrap; gap: 10px;
      }
      .sm-comment-count {
        font-family: 'Cinzel', serif; font-size: 0.62rem;
        letter-spacing: 3px; color: rgba(179,157,219,0.55);
        background: rgba(124,77,255,0.08);
        border: 1px solid rgba(124,77,255,0.18);
        padding: 4px 12px;
      }

      /* ── Write form ── */
      .sm-write-box {
        background: linear-gradient(145deg, rgba(12,5,30,0.55), rgba(3,2,9,0.75));
        border: 1px solid rgba(124,77,255,0.18);
        padding: 22px 24px; margin-bottom: 28px;
        position: relative;
      }
      .sm-write-box::before {
        content: ''; position: absolute; top:0;left:0;right:0; height: 2px;
        background: linear-gradient(90deg, transparent, #7C4DFF, #C9A84C, #7C4DFF, transparent);
      }
      .sm-write-title {
        font-family: 'Cinzel', serif; font-size: 0.78rem;
        letter-spacing: 3px; color: #C9A84C; margin-bottom: 14px;
        text-transform: uppercase;
      }
      .sm-textarea {
        width: 100%; min-height: 100px; resize: vertical;
        background: rgba(0,0,0,0.55); border: 1px solid rgba(124,77,255,0.2);
        color: #F3EEFF; padding: 12px 14px;
        font-family: 'EB Garamond', 'Playfair Display', serif; font-size: 1rem;
        outline: none; transition: border-color .3s; border-radius: 1px;
        display: block; margin-bottom: 12px;
      }
      .sm-textarea::placeholder { color: rgba(243,238,255,0.3); }
      .sm-textarea:focus { border-color: #9575CD; }
      .sm-char-count {
        font-family: 'Cinzel', serif; font-size: 0.58rem; letter-spacing: 2px;
        color: rgba(243,238,255,0.3); text-align: right; margin-bottom: 10px;
      }
      .sm-char-count.warn { color: #FF8A80; }
      .sm-write-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
      .sm-post-btn {
        font-family: 'Cinzel', serif; font-size: 0.7rem; letter-spacing: 3px;
        text-transform: uppercase; padding: 11px 24px;
        background: linear-gradient(135deg, #1A0840, #0A0320);
        border: 1px solid rgba(124,77,255,0.42);
        color: #F3EEFF; cursor: pointer; transition: all .3s;
        position: relative; overflow: hidden;
      }
      .sm-post-btn::before {
        content: ''; position: absolute; inset: 0;
        background: rgba(124,77,255,0.22); opacity: 0; transition: opacity .3s;
      }
      .sm-post-btn:hover::before { opacity: 1; }
      .sm-post-btn:disabled { opacity: 0.45; cursor: wait; }
      .sm-post-btn span { position: relative; z-index: 1; }

      .sm-login-prompt {
        display: flex; align-items: center; justify-content: space-between;
        flex-wrap: wrap; gap: 12px;
        padding: 16px 20px;
        background: rgba(124,77,255,0.06); border: 1px solid rgba(124,77,255,0.18);
        margin-bottom: 24px;
      }
      .sm-login-prompt p {
        font-size: 0.95rem; color: rgba(243,238,255,0.6); font-style: italic;
      }
      .sm-login-prompt-btn {
        font-family: 'Cinzel', serif; font-size: 0.65rem; letter-spacing: 3px;
        text-transform: uppercase; padding: 9px 20px;
        background: rgba(124,77,255,0.12); border: 1px solid rgba(124,77,255,0.35);
        color: #B39DDB; cursor: pointer; transition: all .25s;
      }
      .sm-login-prompt-btn:hover { background: rgba(124,77,255,0.25); color: #F3EEFF; }

      /* ── Comment card ── */
      .sm-comment-card {
        background: linear-gradient(145deg, rgba(12,5,30,0.52), rgba(3,2,9,0.72));
        border: 1px solid rgba(124,77,255,0.1);
        padding: 18px 22px; margin-bottom: 12px;
        border-radius: 1px; position: relative;
        animation: sm-card-in .4s ease;
      }
      @keyframes sm-card-in {
        from { opacity:0; transform: translateY(12px); }
        to   { opacity:1; transform: none; }
      }
      .sm-comment-card.editing {
        border-color: rgba(124,77,255,0.38);
      }
      .sm-comment-hdr {
        display: flex; align-items: center; gap: 10px; margin-bottom: 10px;
      }
      .sm-c-avatar {
        width: 38px; height: 38px; border-radius: 50%; flex-shrink: 0;
        background: linear-gradient(135deg, #7C4DFF, #512DA8);
        display: flex; align-items: center; justify-content: center;
        font-family: 'Cinzel', serif; font-size: 0.9rem; color: #fff; font-weight: 700;
        border: 1px solid rgba(124,77,255,0.3);
      }
      .sm-c-meta { flex: 1; }
      .sm-c-name {
        font-family: 'Cinzel', serif; font-size: 0.78rem;
        color: #E8C96A; letter-spacing: 1px;
      }
      .sm-c-date { font-size: 0.7rem; color: rgba(243,238,255,0.33); }
      .sm-c-edited { font-size: 0.68rem; color: rgba(179,157,219,0.45); font-style: italic; margin-left: 4px; }
      .sm-c-actions { display: flex; gap: 8px; align-items: center; }

      .sm-c-text {
        font-size: 0.96rem; color: rgba(243,238,255,0.72);
        line-height: 1.82; word-break: break-word;
      }

      /* Edit textarea */
      .sm-edit-area {
        width: 100%; min-height: 80px; resize: vertical;
        background: rgba(0,0,0,0.55); border: 1px solid rgba(124,77,255,0.3);
        color: #F3EEFF; padding: 10px 12px;
        font-family: 'EB Garamond', 'Playfair Display', serif; font-size: 0.96rem;
        outline: none; border-radius: 1px; display: block; margin: 10px 0 8px;
      }
      .sm-edit-area:focus { border-color: #9575CD; }
      .sm-edit-row { display: flex; gap: 8px; }

      /* Action buttons */
      .sm-action-btn {
        font-family: 'Cinzel', serif; font-size: 0.56rem; letter-spacing: 1.5px;
        text-transform: uppercase; padding: 5px 11px;
        background: none; border: 1px solid rgba(124,77,255,0.22);
        color: rgba(243,238,255,0.45); cursor: pointer; transition: all .25s;
      }
      .sm-action-btn:hover { border-color: #B39DDB; color: #F3EEFF; }
      .sm-action-btn.like { display: flex; align-items: center; gap: 5px; }
      .sm-action-btn.like.liked { border-color: rgba(124,77,255,0.5); color: #B39DDB; background: rgba(124,77,255,0.1); }
      .sm-action-btn.del:hover { border-color: #FF8A80; color: #FF8A80; }
      .sm-action-btn.save-btn { border-color: rgba(201,168,76,0.35); color: #C9A84C; }
      .sm-action-btn.save-btn:hover { background: rgba(201,168,76,0.1); }

      /* ── Load more ── */
      .sm-load-more {
        text-align: center; margin-top: 20px;
      }
      .sm-load-btn {
        font-family: 'Cinzel', serif; font-size: 0.66rem; letter-spacing: 3px;
        text-transform: uppercase; padding: 10px 28px;
        background: rgba(124,77,255,0.07); border: 1px solid rgba(124,77,255,0.25);
        color: rgba(243,238,255,0.55); cursor: pointer; transition: all .3s;
      }
      .sm-load-btn:hover { background: rgba(124,77,255,0.18); color: #F3EEFF; border-color: #9575CD; }
      .sm-load-btn:disabled { opacity: 0.4; cursor: default; }

      /* Empty state */
      .sm-empty {
        text-align: center; padding: 36px; color: rgba(243,238,255,0.35);
        font-style: italic; font-size: 0.95rem; letter-spacing: 1px;
        border: 1px dashed rgba(124,77,255,0.15);
      }

      /* Error / info */
      .sm-msg { text-align: center; font-size: 0.88rem; color: #FF8A80; font-style: italic; margin: 10px 0; }
    `;
    document.head.appendChild(s);
  }

  /* ─── UTILS ─── */
  function getToken() { return localStorage.getItem(TOKEN_KEY); }

  function authHeaders() {
    const t = getToken();
    return t ? { 'Content-Type': 'application/json', Authorization: 'Bearer ' + t }
             : { 'Content-Type': 'application/json' };
  }

  function timeAgo(iso) {
    const diff = (Date.now() - new Date(iso)) / 1000;
    if (diff < 60)    return 'अभी-अभी';
    if (diff < 3600)  return Math.floor(diff / 60)    + ' मिनट पहले';
    if (diff < 86400) return Math.floor(diff / 3600)  + ' घंटे पहले';
    if (diff < 604800)return Math.floor(diff / 86400) + ' दिन पहले';
    return new Date(iso).toLocaleDateString('hi-IN');
  }

  function escapeHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
            .replace(/"/g,'&quot;').replace(/\n/g,'<br>');
  }

  /* ─── API ─── */
  async function fetchComments(reset = false) {
    if (loading) return;
    loading = true;
    if (reset) { skip = 0; comments = []; }
    try {
      const res  = await fetch(`${API_BASE}/api/comments/${pageId}?skip=${skip}&limit=${LIMIT}`, {
        headers: { Authorization: getToken() ? 'Bearer ' + getToken() : '' }
      });
      const data = await res.json();
      total    = data.total;
      comments = reset ? data.comments : [...comments, ...data.comments];
      skip     = comments.length;
      render();
    } catch (e) {
      console.error('Comments fetch error:', e);
    } finally {
      loading = false;
    }
  }

  async function postComment(text) {
    const res = await fetch(`${API_BASE}/api/comments`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ page_id: pageId, text }),
    });
    if (!res.ok) {
      const d = await res.json();
      throw new Error(d.detail || 'Failed to post comment');
    }
    return res.json();
  }

  async function editComment(id, text) {
    const res = await fetch(`${API_BASE}/api/comments/${id}`, {
      method: 'PUT',
      headers: authHeaders(),
      body: JSON.stringify({ text }),
    });
    if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Failed'); }
    return res.json();
  }

  async function deleteComment(id) {
    const res = await fetch(`${API_BASE}/api/comments/${id}`, {
      method: 'DELETE',
      headers: authHeaders(),
    });
    if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Failed'); }
  }

  async function toggleLike(id) {
    const res = await fetch(`${API_BASE}/api/comments/${id}/like`, {
      method: 'POST',
      headers: authHeaders(),
    });
    if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Failed'); }
    return res.json();
  }

  /* ─── RENDER ─── */
  function getContainer() { return document.getElementById('sm-comments'); }

  function render() {
    const el = getContainer();
    if (!el) return;
    const user  = window.SmAuth ? window.SmAuth.getUser() : null;
    const uid   = user ? user.id : null;

    el.innerHTML = `
      <div class="sm-comments-wrap">
        <div class="sm-comments-heading">
          <span>💬 भक्तों के विचार</span>
          ${total > 0 ? `<span class="sm-comment-count">${total} टिप्पणी</span>` : ''}
        </div>

        ${renderWriteBox(user)}

        <div id="sm-comment-list">
          ${comments.length === 0
            ? '<div class="sm-empty">🕉️ पहले टिप्पणी करने वाले बनें — हर हर महादेव!</div>'
            : comments.map(c => renderCard(c, uid)).join('')}
        </div>

        ${comments.length < total
          ? `<div class="sm-load-more"><button class="sm-load-btn" onclick="SmComments._loadMore()">और टिप्पणियाँ देखें (${total - comments.length} और)</button></div>`
          : ''}
      </div>`;

    // Bind char counter
    const ta = document.getElementById('sm-new-text');
    if (ta) {
      ta.addEventListener('input', () => {
        const cc = document.getElementById('sm-char-count');
        if (cc) {
          const left = 1000 - ta.value.length;
          cc.textContent = `${ta.value.length}/1000`;
          cc.classList.toggle('warn', left < 100);
        }
      });
    }
  }

  function renderWriteBox(user) {
    if (!user) {
      return `
        <div class="sm-login-prompt">
          <p>टिप्पणी करने के लिए लॉगिन करें — भक्तों का समुदाय जुड़ें।</p>
          <button class="sm-login-prompt-btn" onclick="SmAuth.requireLogin()">🔱 लॉगिन / खाता बनाएँ</button>
        </div>`;
    }
    return `
      <div class="sm-write-box">
        <div class="sm-write-title">✦ टिप्पणी लिखें ✦</div>
        <textarea id="sm-new-text" class="sm-textarea"
          placeholder="हर हर महादेव! अपना अनुभव, भाव या प्रश्न साझा करें...&#10;(अधिकतम १००० अक्षर)"
          maxlength="1000"></textarea>
        <div id="sm-char-count" class="sm-char-count">0/1000</div>
        <div class="sm-write-row">
          <button class="sm-post-btn" id="sm-post-btn" onclick="SmComments._submit()">
            <span>🙏 टिप्पणी भेजें</span>
          </button>
          <div class="sm-c-avatar" style="font-size:0.75rem">${user.avatar || user.username[0].toUpperCase()}</div>
          <span style="font-family:'Cinzel',serif;font-size:0.65rem;color:#B39DDB;letter-spacing:1px;">${user.username}</span>
        </div>
        <div id="sm-post-error" class="sm-msg" style="display:none"></div>
      </div>`;
  }

  function renderCard(c, uid) {
    const isOwn     = uid === c.user_id;
    const isEditing = editingId === c.id;
    const isLoggedIn = !!uid;

    return `
      <div class="sm-comment-card${isEditing ? ' editing' : ''}" id="sm-card-${c.id}">
        <div class="sm-comment-hdr">
          <div class="sm-c-avatar">${c.avatar || c.username[0].toUpperCase()}</div>
          <div class="sm-c-meta">
            <div class="sm-c-name">${escapeHtml(c.username)}</div>
            <div class="sm-c-date">
              ${timeAgo(c.created_at)}
              ${c.updated_at !== c.created_at ? '<span class="sm-c-edited">(संपादित)</span>' : ''}
            </div>
          </div>
          <div class="sm-c-actions">
            <!-- Like -->
            <button class="sm-action-btn like ${c.liked_by_me ? 'liked' : ''}"
              onclick="SmComments._like('${c.id}')">
              ${c.liked_by_me ? '❤️' : '🤍'} ${c.likes}
            </button>
            <!-- Edit / Delete (own) -->
            ${isOwn && !isEditing ? `
              <button class="sm-action-btn" onclick="SmComments._startEdit('${c.id}')">✏️</button>
              <button class="sm-action-btn del" onclick="SmComments._delete('${c.id}')">🗑️</button>
            ` : ''}
            ${isEditing ? `
              <button class="sm-action-btn" onclick="SmComments._cancelEdit()">✕ रद्द</button>
            ` : ''}
          </div>
        </div>

        ${isEditing
          ? `<textarea class="sm-edit-area" id="sm-edit-${c.id}" maxlength="1000">${escapeHtml(c.text)}</textarea>
             <div class="sm-edit-row">
               <button class="sm-action-btn save-btn" onclick="SmComments._saveEdit('${c.id}')">💾 सहेजें</button>
             </div>`
          : `<div class="sm-c-text">${escapeHtml(c.text)}</div>`
        }
      </div>`;
  }

  /* ─── ACTIONS ─── */
  async function _submit() {
    const ta   = document.getElementById('sm-new-text');
    const btn  = document.getElementById('sm-post-btn');
    const errEl = document.getElementById('sm-post-error');

    if (!ta) return;
    const text = ta.value.trim();
    if (!text) { errEl.style.display='block'; errEl.textContent='टिप्पणी खाली नहीं हो सकती।'; return; }

    // Check auth
    if (!window.SmAuth || !window.SmAuth.getUser()) {
      window.SmAuth && window.SmAuth.requireLogin();
      return;
    }

    btn.disabled = true; errEl.style.display='none';
    try {
      const c = await postComment(text);
      comments.unshift(c);
      total++;
      ta.value = '';
      const cc = document.getElementById('sm-char-count');
      if (cc) cc.textContent = '0/1000';
      render();
    } catch (e) {
      errEl.style.display = 'block';
      errEl.textContent   = e.message;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function _like(id) {
    if (!window.SmAuth || !window.SmAuth.getUser()) {
      window.SmAuth && window.SmAuth.requireLogin();
      return;
    }
    try {
      const updated = await toggleLike(id);
      const idx     = comments.findIndex(c => c.id === id);
      if (idx !== -1) { comments[idx] = updated; render(); }
    } catch (e) { console.error('Like error:', e); }
  }

  function _startEdit(id) {
    editingId = id; render();
    const ta = document.getElementById('sm-edit-' + id);
    if (ta) { ta.focus(); ta.setSelectionRange(ta.value.length, ta.value.length); }
  }

  function _cancelEdit() { editingId = null; render(); }

  async function _saveEdit(id) {
    const ta   = document.getElementById('sm-edit-' + id);
    if (!ta) return;
    const text = ta.value.trim();
    if (!text) return;
    ta.disabled = true;
    try {
      const updated = await editComment(id, text);
      const idx = comments.findIndex(c => c.id === id);
      if (idx !== -1) comments[idx] = updated;
      editingId = null; render();
    } catch (e) { ta.disabled = false; alert(e.message); }
  }

  async function _delete(id) {
    if (!confirm('यह टिप्पणी हटाएँ? / Delete this comment?')) return;
    try {
      await deleteComment(id);
      comments = comments.filter(c => c.id !== id);
      total    = Math.max(0, total - 1);
      render();
    } catch (e) { alert(e.message); }
  }

  async function _loadMore() {
    await fetchComments(false);
  }

  /* ─── AUTH EVENT LISTENER ─── */
  document.addEventListener('sm-auth-changed', () => render());

  /* ─── PUBLIC API ─── */
  window.SmComments = {
    init(opts = {}) {
      if (opts.apiBase) API_BASE = opts.apiBase;
      injectStyles();
      const el = document.getElementById('sm-comments');
      if (!el) { console.warn('SmComments: no #sm-comments element found'); return; }
      pageId = el.dataset.pageId || document.location.pathname.replace(/\//g, '-').replace(/^-|-$/g, '') || 'default';
      fetchComments(true);
    },
    refresh() { fetchComments(true); },
    _submit, _like, _startEdit, _cancelEdit, _saveEdit, _delete, _loadMore,
  };
})();
