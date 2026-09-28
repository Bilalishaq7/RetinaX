/* ==========================================================================
   RepoAvatar — Standalone UI Component Module
   RetinaX Design System: Clinical White · Slate Navy · Medical Teal
   
   Usage (HTML attribute API):
   ─────────────────────────────────────────────────────────────────────────
   <div class="repo-avatar-mount"
        data-org="RetinaX-Org"
        data-repo="RetinaX"
        data-stars="142"
        data-forks="27"
        data-lang="Rust"
        data-license="MIT"
        data-last-commit-msg="feat: add zk_verifier PLONK circuit"
        data-last-commit-sha="a3f72b1"
        data-last-commit-date="2026-09-20"
        data-github-url="https://github.com/RetinaX-Org/RetinaX"
        data-contributors='[
          {"login":"alice","initials":"AL","color":"teal"},
          {"login":"bob","initials":"BO","color":"blue"}
        ]'
   ></div>
   ─────────────────────────────────────────────────────────────────────────
   JS Programmatic API:
   ─────────────────────────────────────────────────────────────────────────
   const ra = new RepoAvatar(mountEl, {
     org:            'RetinaX-Org',
     repo:           'RetinaX',
     stars:          142,
     forks:          27,
     lang:           'Rust',
     license:        'MIT',
     lastCommitMsg:  'feat: add zk_verifier PLONK circuit',
     lastCommitSha:  'a3f72b1',
     lastCommitDate: '2026-09-20',
     githubUrl:      'https://github.com/RetinaX-Org/RetinaX',
     contributors:   [
       { login: 'alice', initials: 'AL', color: 'teal' },
       { login: 'bob',   initials: 'BO', color: 'blue'  },
     ],
     network:        'Stellar Testnet',      // optional, default shown
     badges:         ['MIT', 'HIPAA', 'CI'], // optional badge list
     orgLogoUrl:     '',                      // optional org logo image URL
     maxContributors: 5,                      // optional, defaults to 5
   });
   ─────────────────────────────────────────────────────────────────────────
   ========================================================================== */

(function (root, factory) {
  /* UMD export — works as ES module, CommonJS, or plain <script> */
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.RepoAvatar = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ------------------------------------------------------------------
     Constants & Helpers
     ------------------------------------------------------------------ */

  /** Predefined badge configurations */
  const BADGE_PRESETS = {
    MIT:     { label: 'MIT License',   cls: 'repo-avatar__badge--green', icon: '⚖️' },
    Apache:  { label: 'Apache 2.0',    cls: 'repo-avatar__badge--green', icon: '⚖️' },
    HIPAA:   { label: 'HIPAA Ready',   cls: 'repo-avatar__badge--teal',  icon: '🏥' },
    GDPR:    { label: 'GDPR Art.25',   cls: 'repo-avatar__badge--teal',  icon: '🇪🇺' },
    CI:      { label: 'CI Passing',    cls: 'repo-avatar__badge--green', icon: '✅' },
    Soroban: { label: 'Soroban v23',   cls: 'repo-avatar__badge--teal',  icon: '⭐' },
    FHIR:    { label: 'FHIR v4',       cls: 'repo-avatar__badge--amber', icon: '📋' },
  };

  /** GitHub Octicon-style SVG star */
  const SVG_STAR = '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.751.751 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25Z"/></svg>';

  /** GitHub Octicon-style SVG fork */
  const SVG_FORK = '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M5 5.372v.878c0 .414.336.75.75.75h4.5a.75.75 0 0 0 .75-.75v-.878a2.25 2.25 0 1 1 1.5 0v.878a2.25 2.25 0 0 1-2.25 2.25h-1.5v2.128a2.251 2.251 0 1 1-1.5 0V8.5h-1.5A2.25 2.25 0 0 1 3.5 6.25v-.878a2.25 2.25 0 1 1 1.5 0ZM5 3.25a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Zm6.75.75a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5Zm-3 8.75a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Z"/></svg>';

  /** GitHub Octicon-style SVG commit */
  const SVG_COMMIT = '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M11.93 8.5a4.002 4.002 0 0 1-7.86 0H.75a.75.75 0 0 1 0-1.5h3.32a4.002 4.002 0 0 1 7.86 0h3.32a.75.75 0 0 1 0 1.5Zm-1.43-.75a2.5 2.5 0 1 0-5 0 2.5 2.5 0 0 0 5 0Z"/></svg>';

  /**
   * Escape HTML to prevent XSS from data values.
   * @param {string} str
   * @returns {string}
   */
  function escHtml(str) {
    if (typeof window !== 'undefined' && window.RetinaXUtils && window.RetinaXUtils.escapeHtml) {
      return window.RetinaXUtils.escapeHtml(str);
    }
    if (typeof str !== 'string') return '';
    return str
      .replace(/&/g,  '&amp;')
      .replace(/</g,  '&lt;')
      .replace(/>/g,  '&gt;')
      .replace(/"/g,  '&quot;')
      .replace(/'/g,  '&#39;');
  }

  /**
   * Format a number with K/M suffix (e.g. 1400 → "1.4k").
   * @param {number|string} n
   * @returns {string}
   */
  function fmtNum(n) {
    if (typeof window !== 'undefined' && window.RetinaXUtils && window.RetinaXUtils.formatCompactNumber) {
      return window.RetinaXUtils.formatCompactNumber(n);
    }
    const num = parseInt(n, 10);
    if (isNaN(num)) return '—';
    if (num >= 1000000) return (num / 1000000).toFixed(1).replace(/\.0$/, '') + 'M';
    if (num >= 1000)    return (num / 1000).toFixed(1).replace(/\.0$/, '') + 'k';
    return String(num);
  }

  /**
   * Format a commit date string relative to now (e.g. "3 days ago").
   * Falls back to ISO format if RetinaXUtils is unavailable.
   * @param {string|Date|number} dateInput
   * @returns {string}
   */
  function fmtCommitDate(dateInput) {
    if (typeof window !== 'undefined' && window.RetinaXUtils && window.RetinaXUtils.formatRelativeTime) {
      return window.RetinaXUtils.formatRelativeTime(dateInput);
    }
    // Minimal fallback
    try {
      const d = new Date(dateInput);
      if (isNaN(d.getTime())) return 'recently';
      const diffDays = Math.floor((Date.now() - d.getTime()) / 86400000);
      if (diffDays < 1)  return 'today';
      if (diffDays === 1) return '1 day ago';
      if (diffDays < 30)  return `${diffDays} days ago`;
      const diffMo = Math.floor(diffDays / 30);
      return diffMo === 1 ? '1 month ago' : `${diffMo} months ago`;
    } catch (_) {
      return 'recently';
    }
  }

  /**
   * Parse contributors — accepts Array or JSON string.
   * @param {Array|string} raw
   * @returns {Array<{login: string, initials: string, color: string, avatarUrl?: string}>}
   */
  function parseContributors(raw) {
    if (!raw) return [];
    if (typeof raw === 'string') {
      try { raw = JSON.parse(raw); } catch (_) { return []; }
    }
    if (!Array.isArray(raw)) return [];
    return raw.map(c => ({
      login:     c.login     || 'unknown',
      initials:  (c.initials || c.login || '??').substring(0, 2).toUpperCase(),
      color:     c.color     || 'navy',
      avatarUrl: c.avatarUrl || '',
    }));
  }

  /* ------------------------------------------------------------------
     HTML Builder
     ------------------------------------------------------------------ */

  /**
   * Build the complete inner HTML for the repo-avatar card.
   * @param {Object} cfg  Resolved configuration object
   * @returns {string} HTML string
   */
  function buildHTML(cfg) {
    const orgDisplay  = escHtml(cfg.org);
    const repoDisplay = escHtml(cfg.repo);
    const langDisplay = escHtml(cfg.lang || 'Rust');
    const networkText = escHtml(cfg.network || 'Stellar Testnet');
    const ghUrl       = escHtml(cfg.githubUrl || `https://github.com/${cfg.org}/${cfg.repo}`);
    const starsStr    = fmtNum(cfg.stars  || 0);
    const forksStr    = fmtNum(cfg.forks  || 0);
    const commitMsg   = escHtml(cfg.lastCommitMsg  || 'Initial commit');
    const commitSha   = escHtml((cfg.lastCommitSha || 'abc1234').substring(0, 7));
    const commitDate  = fmtCommitDate(cfg.lastCommitDate || new Date());
    const maxContrib  = typeof cfg.maxContributors === 'number' ? cfg.maxContributors : 5;
    const contributors = (cfg.contributors || []).slice(0, maxContrib + 1);
    const visibleContribs = contributors.slice(0, maxContrib);
    const overflow = Math.max(0, (cfg.contributors || []).length - maxContrib);

    /* --- Build org logo --- */
    const orgLogoInner = cfg.orgLogoUrl
      ? `<img src="${escHtml(cfg.orgLogoUrl)}" alt="${orgDisplay} logo" loading="lazy">`
      : escHtml((cfg.org || 'R').charAt(0).toUpperCase());

    /* --- Build badge HTML --- */
    const badgeKeys = Array.isArray(cfg.badges) && cfg.badges.length
      ? cfg.badges
      : ['MIT', 'HIPAA', 'CI'];

    const badgesHTML = badgeKeys.map(key => {
      const preset = BADGE_PRESETS[key];
      if (!preset) return '';
      return `<span class="repo-avatar__badge ${preset.cls}" aria-label="${escHtml(preset.label)}">${preset.icon} ${escHtml(preset.label)}</span>`;
    }).join('');

    /* --- Build contributor stack --- */
    const contribHTML = visibleContribs.map(c => {
      const inner = c.avatarUrl
        ? `<img src="${escHtml(c.avatarUrl)}" alt="${escHtml(c.login)}" loading="lazy">`
        : escHtml(c.initials);
      return `<div class="repo-avatar__avatar" data-color="${escHtml(c.color)}" data-tooltip="@${escHtml(c.login)}" role="img" aria-label="Contributor @${escHtml(c.login)}">${inner}</div>`;
    }).join('');

    const overflowHTML = overflow > 0
      ? `<div class="repo-avatar__avatar repo-avatar__avatar-overflow" data-color="navy" aria-label="${overflow} more contributors">+${overflow}</div>`
      : '';

    return `
      <!-- Dark header banner -->
      <div class="repo-avatar__banner" aria-label="Repository: ${orgDisplay}/${repoDisplay}">
        <div class="repo-avatar__banner-left">
          <div class="repo-avatar__org-icon" aria-hidden="true">${orgLogoInner}</div>
          <div class="repo-avatar__repo-path">
            <span class="repo-avatar__org-name">${orgDisplay} /</span>
            <span class="repo-avatar__repo-name">${repoDisplay}</span>
          </div>
        </div>
        <div class="repo-avatar__network-pill" role="status" aria-label="Network: ${networkText}">
          <span class="repo-avatar__network-dot" aria-hidden="true"></span>
          ${networkText}
        </div>
      </div>

      <!-- Card body -->
      <div class="repo-avatar__body">

        <!-- Stars / Forks / Language -->
        <div class="repo-avatar__stats" aria-label="Repository statistics">
          <div class="repo-avatar__stat" title="${escHtml(String(cfg.stars || 0))} stars">
            <span class="repo-avatar__stat-icon" aria-hidden="true">${SVG_STAR}</span>
            <span>${starsStr}</span>
          </div>
          <div class="repo-avatar__stat" title="${escHtml(String(cfg.forks || 0))} forks">
            <span class="repo-avatar__stat-icon" aria-hidden="true">${SVG_FORK}</span>
            <span>${forksStr}</span>
          </div>
          <div class="repo-avatar__stat" title="Primary language: ${langDisplay}">
            <span class="repo-avatar__lang-dot" data-lang="${langDisplay}" aria-hidden="true"></span>
            <span>${langDisplay}</span>
          </div>
        </div>

        <!-- Contributors -->
        <div class="repo-avatar__contributors">
          <span class="repo-avatar__contributors-label">Contributors</span>
          <div class="repo-avatar__avatar-stack" role="list" aria-label="Contributor avatars">
            ${contribHTML}
            ${overflowHTML}
          </div>
        </div>

        <!-- Last Commit -->
        <div class="repo-avatar__commit" aria-label="Last commit: ${commitMsg}">
          <span class="repo-avatar__commit-icon" aria-hidden="true">${SVG_COMMIT}</span>
          <div class="repo-avatar__commit-details">
            <span class="repo-avatar__commit-message">${commitMsg}</span>
            <span class="repo-avatar__commit-meta">
              <span class="repo-avatar__commit-sha">${commitSha}</span>
              &nbsp;·&nbsp;${escHtml(commitDate)}
            </span>
          </div>
        </div>

        <!-- Badges -->
        <div class="repo-avatar__badges" aria-label="Repository badges">
          ${badgesHTML}
        </div>
      </div>

      <!-- Footer CTAs -->
      <div class="repo-avatar__footer">
        <a
          href="${ghUrl}"
          target="_blank"
          rel="noopener noreferrer"
          class="repo-avatar__cta repo-avatar__cta--primary"
          aria-label="View ${repoDisplay} on GitHub"
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
          View on GitHub
        </a>
        <a
          href="${ghUrl}/issues"
          target="_blank"
          rel="noopener noreferrer"
          class="repo-avatar__cta repo-avatar__cta--secondary"
          aria-label="View open issues for ${repoDisplay}"
        >
          Issues
        </a>
      </div>
    `.trim();
  }

  /**
   * Build skeleton loading HTML.
   * @returns {string}
   */
  function buildSkeletonHTML() {
    return `
      <div class="repo-avatar__banner">
        <div class="repo-avatar__banner-left">
          <div class="repo-avatar__org-icon" aria-hidden="true">R</div>
          <div class="repo-avatar__repo-path">
            <span class="ra-skel" style="height:10px;width:80px;display:block;margin-bottom:4px;"></span>
            <span class="ra-skel" style="height:14px;width:120px;display:block;"></span>
          </div>
        </div>
        <div class="ra-skel" style="height:24px;width:110px;border-radius:20px;"></div>
      </div>
      <div class="repo-avatar__skeleton">
        <div class="ra-skel ra-skel--title"></div>
        <div style="display:flex;gap:8px;">
          <div class="ra-skel ra-skel--avatar"></div>
          <div class="ra-skel ra-skel--avatar"></div>
          <div class="ra-skel ra-skel--avatar"></div>
        </div>
        <div class="ra-skel ra-skel--line"></div>
        <div class="ra-skel ra-skel--short"></div>
      </div>
    `.trim();
  }

  /**
   * Build error state HTML.
   * @param {string} message
   * @returns {string}
   */
  function buildErrorHTML(message) {
    return `
      <div class="repo-avatar__banner">
        <div class="repo-avatar__banner-left">
          <div class="repo-avatar__org-icon" aria-hidden="true">!</div>
          <div class="repo-avatar__repo-path">
            <span class="repo-avatar__org-name">Error</span>
            <span class="repo-avatar__repo-name">Failed to load</span>
          </div>
        </div>
      </div>
      <div class="repo-avatar__error" role="alert">
        <span class="repo-avatar__error-icon">⚠️</span>
        <span>${escHtml(message || 'Could not load repository data.')}</span>
      </div>
    `.trim();
  }

  /* ------------------------------------------------------------------
     RepoAvatar Class
     ------------------------------------------------------------------ */

  /**
   * @class RepoAvatar
   * Standalone repository avatar card component for the RetinaX website.
   *
   * @param {HTMLElement} mountEl  Container element to render into
   * @param {Object}      [opts]   Configuration options (see module header for full list)
   */
  function RepoAvatar(mountEl, opts) {
    if (!(this instanceof RepoAvatar)) {
      return new RepoAvatar(mountEl, opts);
    }

    if (!(mountEl instanceof HTMLElement)) {
      throw new TypeError('RepoAvatar: mountEl must be an HTMLElement');
    }

    this._mount = mountEl;
    this._cfg   = null;
    this._card  = null;

    /* Resolve initial config from options or data-* attributes */
    const cfg = this._resolveConfig(opts || {});
    this._cfg = cfg;

    this._render(cfg);
  }

  /**
   * Resolve merged configuration from passed options and element data-* attributes.
   * Explicit options take precedence over data attributes.
   * @private
   */
  RepoAvatar.prototype._resolveConfig = function (opts) {
    const el = this._mount;

    /**
     * Read a data attribute, falling back to an option value.
     * @param {string} attr  e.g. 'org'
     * @param {*}      fallback
     * @returns {*}
     */
    const d = (attr, fallback) => {
      const raw = el.dataset[attr];
      if (raw !== undefined && raw !== '') return raw;
      if (opts[attr] !== undefined)        return opts[attr];
      /* camelCase fallbacks for common attrs */
      const camel = attr.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      if (opts[camel] !== undefined)       return opts[camel];
      return fallback;
    };

    return {
      org:            d('org',            'RetinaX-Org'),
      repo:           d('repo',           'RetinaX'),
      stars:          parseInt(d('stars',  0), 10),
      forks:          parseInt(d('forks',  0), 10),
      lang:           d('lang',           'Rust'),
      license:        d('license',        'MIT'),
      lastCommitMsg:  d('lastCommitMsg',  d('last-commit-msg', 'chore: update dependencies')),
      lastCommitSha:  d('lastCommitSha',  d('last-commit-sha', 'abc1234')),
      lastCommitDate: d('lastCommitDate', d('last-commit-date', new Date().toISOString())),
      githubUrl:      d('githubUrl',      d('github-url', '')),
      network:        d('network',        'Stellar Testnet'),
      orgLogoUrl:     d('orgLogoUrl',     d('org-logo-url', '')),
      maxContributors: parseInt(d('maxContributors', d('max-contributors', 5)), 10),
      contributors:   parseContributors(
        opts.contributors !== undefined
          ? opts.contributors
          : el.dataset.contributors || ''
      ),
      badges: (() => {
        const raw = opts.badges !== undefined
          ? opts.badges
          : el.dataset.badges;
        if (Array.isArray(raw)) return raw;
        if (typeof raw === 'string' && raw) return raw.split(',').map(s => s.trim());
        return ['MIT', 'HIPAA', 'CI'];
      })(),
    };
  };

  /**
   * Render the component into the mount element.
   * @private
   * @param {Object} cfg  Resolved configuration
   */
  RepoAvatar.prototype._render = function (cfg) {
    const mount = this._mount;

    /* Create or reuse the card wrapper */
    let card = mount.querySelector('.repo-avatar-component');
    if (!card) {
      card = document.createElement('div');
      card.className = 'repo-avatar-component';
      mount.appendChild(card);
    }
    this._card = card;

    /* Set ARIA role for the card */
    card.setAttribute('role', 'region');
    card.setAttribute('aria-label', `Repository card: ${cfg.org}/${cfg.repo}`);

    /* Inject content */
    card.innerHTML = buildHTML(cfg);
  };

  /**
   * Show a loading skeleton state.
   * Useful while fetching live GitHub data.
   */
  RepoAvatar.prototype.showLoading = function () {
    if (!this._card) return;
    this._card.classList.add('is-loading');
    this._card.innerHTML = buildSkeletonHTML();
  };

  /**
   * Show an error state with an optional message.
   * @param {string} [message]
   */
  RepoAvatar.prototype.showError = function (message) {
    if (!this._card) return;
    this._card.classList.remove('is-loading');
    this._card.innerHTML = buildErrorHTML(message);
  };

  /**
   * Update the component with new configuration and re-render.
   * @param {Object} newOpts  Partial or complete options object
   */
  RepoAvatar.prototype.update = function (newOpts) {
    if (!this._card) return;
    Object.assign(this._cfg, newOpts);
    this._card.classList.remove('is-loading');
    this._card.innerHTML = buildHTML(this._cfg);
  };

  /**
   * Unmount / destroy the component, removing its DOM node.
   */
  RepoAvatar.prototype.destroy = function () {
    if (this._card && this._card.parentNode) {
      this._card.parentNode.removeChild(this._card);
    }
    this._card  = null;
    this._cfg   = null;
    this._mount = null;
  };

  /* ------------------------------------------------------------------
     Auto-init: scan DOM for [data-repo-avatar] or .repo-avatar-mount
     and instantiate automatically on DOMContentLoaded.
     ------------------------------------------------------------------ */

  /**
   * Auto-initialise all mount points found in the document.
   * Called automatically when the script is loaded in a browser.
   */
  RepoAvatar.autoInit = function () {
    const mounts = document.querySelectorAll('[data-repo-avatar], .repo-avatar-mount');
    mounts.forEach(function (el) {
      if (el.__repoAvatar) return; // already initialised
      el.__repoAvatar = new RepoAvatar(el);
    });
  };

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', RepoAvatar.autoInit);
    } else {
      // DOM already ready
      RepoAvatar.autoInit();
    }
  }

  return RepoAvatar;
}));
