/* ==========================================================================
   PatientCard — Standalone UI Component Module
   RetinaX Design System: Clinical White · Slate Navy · Medical Teal
   
   Usage (HTML attribute API):
   ─────────────────────────────────────────────────────────────────────────
   <div class="patient-card-mount"
        data-patient-id="G45XY"
        data-patient-name="John Doe"
        data-age="42"
        data-gender="M"
        data-last-visit="2026-09-15"
        data-next-appointment="2026-10-01T14:30:00Z"
        data-conditions='["Myopia", "Astigmatism"]'
        data-prescriptions='[
          {"type":"OD", "sphere":"-2.50", "cylinder":"-0.75", "axis":"180"},
          {"type":"OS", "sphere":"-2.75", "cylinder":"-0.50", "axis":"175"}
        ]'
        data-recent-exams="3"
        data-care-provider="Dr. Smith"
   ></div>
   ─────────────────────────────────────────────────────────────────────────
   JS Programmatic API:
   ─────────────────────────────────────────────────────────────────────────
   const pc = new PatientCard(mountEl, {
     patientId:        'G45XY',
     patientName:      'John Doe',
     age:              42,
     gender:           'M',
     lastVisit:        '2026-09-15',
     nextAppointment:  '2026-10-01T14:30:00Z',
     conditions:       ['Myopia', 'Astigmatism'],
     prescriptions: [
       { type: 'OD', sphere: '-2.50', cylinder: '-0.75', axis: '180' },
       { type: 'OS', sphere: '-2.75', cylinder: '-0.50', axis: '175' },
     ],
     recentExams:      3,
     careProvider:     'Dr. Smith',
     accessLevel:      'Read',           // optional: Read, Write, Admin
     avatarUrl:        '',               // optional patient avatar
     showSensitive:    true,             // optional: show/hide sensitive data
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
    root.PatientCard = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ------------------------------------------------------------------
     Constants & Helpers
     ------------------------------------------------------------------ */

  /** Condition severity badge configurations */
  const CONDITION_SEVERITY = {
    Myopia:       { cls: 'patient-card__condition--mild',    icon: '👓' },
    Astigmatism:  { cls: 'patient-card__condition--mild',    icon: '👁️' },
    Glaucoma:     { cls: 'patient-card__condition--serious', icon: '⚠️' },
    Cataracts:    { cls: 'patient-card__condition--moderate',icon: '🔍' },
    Diabetic:     { cls: 'patient-card__condition--serious', icon: '🩺' },
  };

  /** Medical icons SVG */
  const SVG_CALENDAR = '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M4.75 0a.75.75 0 0 1 .75.75V2h5V.75a.75.75 0 0 1 1.5 0V2h1.25c.966 0 1.75.784 1.75 1.75v10.5A1.75 1.75 0 0 1 13.25 16H2.75A1.75 1.75 0 0 1 1 14.25V3.75C1 2.784 1.784 2 2.75 2H4V.75A.75.75 0 0 1 4.75 0ZM2.5 7.5v6.75c0 .138.112.25.25.25h10.5a.25.25 0 0 0 .25-.25V7.5Zm10.75-4H2.75a.25.25 0 0 0-.25.25V6h11V3.75a.25.25 0 0 0-.25-.25Z"/></svg>';
  const SVG_MEDICAL = '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M3.5 0A1.5 1.5 0 0 0 2 1.5v13A1.5 1.5 0 0 0 3.5 16h9a1.5 1.5 0 0 0 1.5-1.5v-13A1.5 1.5 0 0 0 12.5 0h-9Zm0 1.5h9v13h-9v-13ZM7 4.75A.75.75 0 0 1 7.75 4h.5a.75.75 0 0 1 0 1.5h-.5A.75.75 0 0 1 7 4.75ZM5.75 7a.75.75 0 0 0 0 1.5h4.5a.75.75 0 0 0 0-1.5h-4.5ZM5 10.25a.75.75 0 0 1 .75-.75h4.5a.75.75 0 0 1 0 1.5h-4.5a.75.75 0 0 1-.75-.75Z"/></svg>';
  const SVG_CLOCK = '<svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0ZM1.5 8a6.5 6.5 0 1 0 13 0 6.5 6.5 0 0 0-13 0Zm7-3.25v2.992l2.028.812a.75.75 0 0 1-.557 1.392l-2.5-1A.751.751 0 0 1 7 8.25v-3.5a.75.75 0 0 1 1.5 0Z"/></svg>';

  /**
   * Escape HTML to prevent XSS from data values.
   * @param {string} str
   * @returns {string}
   */
  function escHtml(str) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/&/g,  '&amp;')
      .replace(/</g,  '&lt;')
      .replace(/>/g,  '&gt;')
      .replace(/"/g,  '&quot;')
      .replace(/'/g,  '&#39;');
  }

  /**
   * Format a date string using RetinaXUtils if available.
   * @param {string|Date|number} dateInput
   * @param {string} format
   * @returns {string}
   */
  function fmtDate(dateInput, format) {
    if (typeof window !== 'undefined' && window.RetinaXUtils && window.RetinaXUtils.formatDate) {
      return window.RetinaXUtils.formatDate(dateInput, format);
    }
    // Minimal fallback
    try {
      const d = new Date(dateInput);
      if (isNaN(d.getTime())) return '—';
      const year = d.getFullYear();
      const month = String(d.getMonth() + 1).padStart(2, '0');
      const day = String(d.getDate()).padStart(2, '0');
      return `${year}-${month}-${day}`;
    } catch (_) {
      return '—';
    }
  }

  /**
   * Format relative time if RetinaXUtils available, else fallback.
   * @param {string|Date|number} dateInput
   * @returns {string}
   */
  function fmtRelative(dateInput) {
    if (typeof window !== 'undefined' && window.RetinaXUtils && window.RetinaXUtils.formatRelativeTime) {
      return window.RetinaXUtils.formatRelativeTime(dateInput);
    }
    // Minimal fallback
    try {
      const d = new Date(dateInput);
      if (isNaN(d.getTime())) return 'recently';
      const diffDays = Math.floor((Date.now() - d.getTime()) / 86400000);
      if (diffDays < 0)  return `in ${Math.abs(diffDays)} days`;
      if (diffDays < 1)  return 'today';
      if (diffDays === 1) return 'yesterday';
      return `${diffDays} days ago`;
    } catch (_) {
      return 'recently';
    }
  }

  /**
   * Parse JSON array or return array if already parsed.
   * @param {Array|string} raw
   * @returns {Array}
   */
  function parseArray(raw) {
    if (!raw) return [];
    if (Array.isArray(raw)) return raw;
    if (typeof raw === 'string') {
      try { return JSON.parse(raw); } catch (_) { return []; }
    }
    return [];
  }

  /**
   * Get patient initials from full name.
   * @param {string} name
   * @returns {string}
   */
  function getInitials(name) {
    if (!name) return '??';
    const parts = name.split(' ');
    if (parts.length >= 2) {
      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    }
    return name.substring(0, 2).toUpperCase();
  }

  /* ------------------------------------------------------------------
     HTML Builder
     ------------------------------------------------------------------ */

  /**
   * Build the complete inner HTML for the patient-card.
   * @param {Object} cfg  Resolved configuration object
   * @returns {string} HTML string
   */
  function buildHTML(cfg) {
    const patientId    = escHtml(cfg.patientId || 'N/A');
    const patientName  = escHtml(cfg.patientName || 'Unknown Patient');
    const age          = cfg.age || '—';
    const gender       = escHtml(cfg.gender || 'N/A');
    const lastVisit    = fmtDate(cfg.lastVisit, 'MMM DD, YYYY');
    const nextAppt     = cfg.nextAppointment ? fmtDate(cfg.nextAppointment, 'MMM DD, YYYY') : 'None scheduled';
    const nextApptTime = cfg.nextAppointment ? fmtRelative(cfg.nextAppointment) : '';
    const recentExams  = cfg.recentExams || 0;
    const careProvider = escHtml(cfg.careProvider || 'Not assigned');
    const accessLevel  = escHtml(cfg.accessLevel || 'Read');
    const showSensitive = cfg.showSensitive !== false;

    /* --- Build patient avatar --- */
    const avatarInner = cfg.avatarUrl
      ? `<img src="${escHtml(cfg.avatarUrl)}" alt="${patientName} avatar" loading="lazy">`
      : escHtml(getInitials(cfg.patientName));

    /* --- Build conditions list --- */
    const conditions = parseArray(cfg.conditions);
    const conditionsHTML = conditions.length > 0
      ? conditions.map(cond => {
          const severity = CONDITION_SEVERITY[cond] || { cls: 'patient-card__condition--mild', icon: '📋' };
          return `<span class="patient-card__condition ${severity.cls}" aria-label="${escHtml(cond)}">${severity.icon} ${escHtml(cond)}</span>`;
        }).join('')
      : '<span class="patient-card__no-data">No conditions recorded</span>';

    /* --- Build prescriptions --- */
    const prescriptions = parseArray(cfg.prescriptions);
    const rxHTML = prescriptions.length > 0 && showSensitive
      ? prescriptions.map(rx => {
          return `
            <div class="patient-card__rx">
              <span class="patient-card__rx-type">${escHtml(rx.type || 'OD')}</span>
              <span class="patient-card__rx-detail">SPH: ${escHtml(rx.sphere || '0.00')}</span>
              <span class="patient-card__rx-detail">CYL: ${escHtml(rx.cylinder || '0.00')}</span>
              <span class="patient-card__rx-detail">AXIS: ${escHtml(rx.axis || '—')}</span>
            </div>
          `;
        }).join('')
      : '<div class="patient-card__no-data">No prescriptions recorded</div>';

    return `
      <!-- Header with patient identity -->
      <div class="patient-card__header" aria-label="Patient: ${patientName}">
        <div class="patient-card__avatar" aria-hidden="true">${avatarInner}</div>
        <div class="patient-card__identity">
          <div class="patient-card__name">${patientName}</div>
          <div class="patient-card__meta">
            <span class="patient-card__id">ID: ${patientId}</span>
            <span class="patient-card__demo">${age}y ${gender}</span>
          </div>
        </div>
        <div class="patient-card__access-badge" data-level="${accessLevel.toLowerCase()}" role="status" aria-label="Access level: ${accessLevel}">
          ${accessLevel}
        </div>
      </div>

      <!-- Body with medical details -->
      <div class="patient-card__body">

        <!-- Care provider -->
        <div class="patient-card__section">
          <div class="patient-card__section-label">
            <span class="patient-card__icon" aria-hidden="true">${SVG_MEDICAL}</span>
            Care Provider
          </div>
          <div class="patient-card__section-value">${careProvider}</div>
        </div>

        <!-- Last visit -->
        <div class="patient-card__section">
          <div class="patient-card__section-label">
            <span class="patient-card__icon" aria-hidden="true">${SVG_CALENDAR}</span>
            Last Visit
          </div>
          <div class="patient-card__section-value">${escHtml(lastVisit)}</div>
        </div>

        <!-- Next appointment -->
        <div class="patient-card__section">
          <div class="patient-card__section-label">
            <span class="patient-card__icon" aria-hidden="true">${SVG_CLOCK}</span>
            Next Appointment
          </div>
          <div class="patient-card__section-value">
            ${escHtml(nextAppt)}
            ${nextApptTime ? `<span class="patient-card__relative-time">(${escHtml(nextApptTime)})</span>` : ''}
          </div>
        </div>

        <!-- Recent exams count -->
        <div class="patient-card__stats">
          <div class="patient-card__stat">
            <span class="patient-card__stat-value">${recentExams}</span>
            <span class="patient-card__stat-label">Recent Exams</span>
          </div>
        </div>

        <!-- Conditions -->
        <div class="patient-card__section">
          <div class="patient-card__section-label">Conditions</div>
          <div class="patient-card__conditions">
            ${conditionsHTML}
          </div>
        </div>

        <!-- Prescriptions (sensitive data) -->
        ${showSensitive ? `
          <div class="patient-card__section">
            <div class="patient-card__section-label">Current Prescription</div>
            <div class="patient-card__prescriptions">
              ${rxHTML}
            </div>
          </div>
        ` : ''}
      </div>

      <!-- Footer actions -->
      <div class="patient-card__footer">
        <button class="patient-card__btn patient-card__btn--primary" aria-label="View full medical record for ${patientName}">
          View Record
        </button>
        <button class="patient-card__btn patient-card__btn--secondary" aria-label="Schedule appointment for ${patientName}">
          Schedule
        </button>
      </div>
    `.trim();
  }

  /**
   * Build skeleton loading HTML.
   * @returns {string}
   */
  function buildSkeletonHTML() {
    return `
      <div class="patient-card__header">
        <div class="patient-card__avatar pc-skel-circle" aria-hidden="true"></div>
        <div style="flex:1;">
          <div class="pc-skel pc-skel-title"></div>
          <div class="pc-skel pc-skel-line" style="width:60%;"></div>
        </div>
      </div>
      <div class="patient-card__skeleton">
        <div class="pc-skel pc-skel-line"></div>
        <div class="pc-skel pc-skel-line" style="width:80%;"></div>
        <div class="pc-skel pc-skel-line" style="width:70%;"></div>
        <div style="display:flex;gap:8px;margin-top:12px;">
          <div class="pc-skel pc-skel-badge"></div>
          <div class="pc-skel pc-skel-badge"></div>
        </div>
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
      <div class="patient-card__header">
        <div class="patient-card__avatar" aria-hidden="true">!</div>
        <div class="patient-card__identity">
          <div class="patient-card__name">Error</div>
          <div class="patient-card__meta">Failed to load patient data</div>
        </div>
      </div>
      <div class="patient-card__error" role="alert">
        <span class="patient-card__error-icon">⚠️</span>
        <span>${escHtml(message || 'Could not load patient data.')}</span>
      </div>
    `.trim();
  }

  /* ------------------------------------------------------------------
     PatientCard Class
     ------------------------------------------------------------------ */

  /**
   * @class PatientCard
   * Standalone patient card component for the RetinaX healthcare system.
   *
   * @param {HTMLElement} mountEl  Container element to render into
   * @param {Object}      [opts]   Configuration options (see module header for full list)
   */
  function PatientCard(mountEl, opts) {
    if (!(this instanceof PatientCard)) {
      return new PatientCard(mountEl, opts);
    }

    if (!(mountEl instanceof HTMLElement)) {
      throw new TypeError('PatientCard: mountEl must be an HTMLElement');
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
  PatientCard.prototype._resolveConfig = function (opts) {
    const el = this._mount;

    /**
     * Read a data attribute, falling back to an option value.
     * @param {string} attr  e.g. 'patientId'
     * @param {*}      fallback
     * @returns {*}
     */
    const d = (attr, fallback) => {
      const kebab = attr.replace(/([A-Z])/g, '-$1').toLowerCase();
      const raw = el.dataset[attr] || el.dataset[kebab.replace(/^-/, '')];
      if (raw !== undefined && raw !== '') return raw;
      if (opts[attr] !== undefined)        return opts[attr];
      return fallback;
    };

    return {
      patientId:        d('patientId',       'N/A'),
      patientName:      d('patientName',     'Unknown Patient'),
      age:              parseInt(d('age',    0), 10) || 0,
      gender:           d('gender',          'N/A'),
      lastVisit:        d('lastVisit',       new Date().toISOString()),
      nextAppointment:  d('nextAppointment', ''),
      conditions:       parseArray(opts.conditions !== undefined ? opts.conditions : el.dataset.conditions),
      prescriptions:    parseArray(opts.prescriptions !== undefined ? opts.prescriptions : el.dataset.prescriptions),
      recentExams:      parseInt(d('recentExams', 0), 10) || 0,
      careProvider:     d('careProvider',    'Not assigned'),
      accessLevel:      d('accessLevel',     'Read'),
      avatarUrl:        d('avatarUrl',       ''),
      showSensitive:    d('showSensitive',   'true') !== 'false',
    };
  };

  /**
   * Render the component into the mount element.
   * @private
   * @param {Object} cfg  Resolved configuration
   */
  PatientCard.prototype._render = function (cfg) {
    const mount = this._mount;

    /* Create or reuse the card wrapper */
    let card = mount.querySelector('.patient-card-component');
    if (!card) {
      card = document.createElement('div');
      card.className = 'patient-card-component';
      mount.appendChild(card);
    }
    this._card = card;

    /* Set ARIA role for the card */
    card.setAttribute('role', 'region');
    card.setAttribute('aria-label', `Patient card: ${cfg.patientName}`);

    /* Inject content */
    card.innerHTML = buildHTML(cfg);
  };

  /**
   * Show a loading skeleton state.
   * Useful while fetching patient data from blockchain or backend.
   */
  PatientCard.prototype.showLoading = function () {
    if (!this._card) return;
    this._card.classList.add('is-loading');
    this._card.innerHTML = buildSkeletonHTML();
  };

  /**
   * Show an error state with an optional message.
   * @param {string} [message]
   */
  PatientCard.prototype.showError = function (message) {
    if (!this._card) return;
    this._card.classList.remove('is-loading');
    this._card.innerHTML = buildErrorHTML(message);
  };

  /**
   * Update the component with new configuration and re-render.
   * @param {Object} newOpts  Partial or complete options object
   */
  PatientCard.prototype.update = function (newOpts) {
    if (!this._card) return;
    Object.assign(this._cfg, newOpts);
    this._card.classList.remove('is-loading');
    this._card.innerHTML = buildHTML(this._cfg);
  };

  /**
   * Unmount / destroy the component, removing its DOM node.
   */
  PatientCard.prototype.destroy = function () {
    if (this._card && this._card.parentNode) {
      this._card.parentNode.removeChild(this._card);
    }
    this._card  = null;
    this._cfg   = null;
    this._mount = null;
  };

  /* ------------------------------------------------------------------
     Auto-init: scan DOM for [data-patient-card] or .patient-card-mount
     and instantiate automatically on DOMContentLoaded.
     ------------------------------------------------------------------ */

  /**
   * Auto-initialise all mount points found in the document.
   * Called automatically when the script is loaded in a browser.
   */
  PatientCard.autoInit = function () {
    const mounts = document.querySelectorAll('[data-patient-card], .patient-card-mount');
    mounts.forEach(function (el) {
      if (el.__patientCard) return; // already initialised
      el.__patientCard = new PatientCard(el);
    });
  };

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', PatientCard.autoInit);
    } else {
      // DOM already ready
      PatientCard.autoInit();
    }
  }

  return PatientCard;
}));
