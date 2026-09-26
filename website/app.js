/* ==========================================================================
   RetinaX — Clinical Interactive JS & GSAP + AOS Mega Animations
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Initialize AOS (Animate On Scroll)
  if (typeof AOS !== 'undefined') {
    AOS.init({
      duration: 800,
      easing: 'ease-out-cubic',
      once: true,
      offset: 100
    });
  }

  // 2. Initialize GSAP Entrance Animations
  initGSAPAnimations();

  // 3. Initialize Interactive Simulators
  initDemoTabs();
  initRBACSimulator();
  initZKSimulator();
  initAISimulator();
  initFHIRSimulator();
  initDataFetchSimulator();
  initModal();
});

/* ==========================================================================
   GSAP Mega Animation Timelines
   ========================================================================== */
function initGSAPAnimations() {
  if (typeof gsap === 'undefined') return;

  // Hero Section Staggered Entrance
  const heroTl = gsap.timeline();

  heroTl.from('.hero-tag', {
    opacity: 0,
    y: -20,
    duration: 0.6,
    ease: 'power2.out'
  })
  .from('.hero-title', {
    opacity: 0,
    y: 30,
    duration: 0.8,
    ease: 'power3.out'
  }, '-=0.3')
  .from('.hero-sub', {
    opacity: 0,
    y: 20,
    duration: 0.7,
    ease: 'power2.out'
  }, '-=0.4')
  .from('.hero-cta-group .btn', {
    opacity: 0,
    y: 20,
    stagger: 0.15,
    duration: 0.6,
    ease: 'back.out(1.7)'
  }, '-=0.4')
  .from('.hero-image-wrapper', {
    opacity: 0,
    scale: 0.95,
    duration: 0.9,
    ease: 'power3.out'
  }, '-=0.8');

  // GSAP Hover Micro-Interactions on Contract Cards
  const cards = document.querySelectorAll('.contract-card, .segment-img-card');
  cards.forEach(card => {
    card.addEventListener('mouseenter', () => {
      gsap.to(card, { y: -6, duration: 0.25, ease: 'power2.out' });
    });
    card.addEventListener('mouseleave', () => {
      gsap.to(card, { y: 0, duration: 0.25, ease: 'power2.out' });
    });
  });
}

/* ==========================================================================
   Tab Switching Logic
   ========================================================================== */
function initDemoTabs() {
  const tabs = document.querySelectorAll('.demo-tab-btn');
  const panels = document.querySelectorAll('.demo-tab-panel');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const targetId = `panel-${tab.dataset.tab}`;
      const targetPanel = document.getElementById(targetId);
      
      if (targetPanel) {
        targetPanel.classList.add('active');
        if (typeof gsap !== 'undefined') {
          gsap.fromTo(targetPanel, { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.4, ease: 'power2.out' });
        }
      }
    });
  });
}

/* ==========================================================================
   RBAC Access Control Simulator
   ========================================================================== */
function initRBACSimulator() {
  const durSlider = document.getElementById('dur-slider');
  const durVal = document.getElementById('dur-val');
  const doctorSelect = document.getElementById('select-doctor');
  const grantBtn = document.getElementById('btn-grant-access');
  const previewCode = document.getElementById('preview-rbac-code');

  if (durSlider && durVal) {
    durSlider.addEventListener('input', (e) => {
      durVal.textContent = e.target.value;
      updateRBACPreview();
    });
  }

  if (doctorSelect) {
    doctorSelect.addEventListener('change', updateRBACPreview);
  }

  if (grantBtn) {
    grantBtn.closest('form').addEventListener('submit', (e) => {
      e.preventDefault();
      grantBtn.textContent = '⚡ Executing Soroban require_auth()...';
      grantBtn.style.opacity = '0.7';

      setTimeout(() => {
        grantBtn.textContent = '✅ Access Granted On-Chain!';
        grantBtn.style.opacity = '1';
        updateRBACPreview(true);

        setTimeout(() => {
          grantBtn.textContent = 'Execute Soroban Auth';
        }, 2500);
      }, 700);
    });
  }

  function updateRBACPreview(executed = false) {
    const doctor = doctorSelect ? doctorSelect.value : 'GAB...DR_SMITH_OPTOMETRY';
    const hours = durSlider ? durSlider.value : '24';
    const statusStr = executed ? 'SUCCESS (LEDGER_ENFORCED)' : 'PENDING_SIGNATURE';

    if (previewCode) {
      previewCode.textContent = `// Soroban Call: contracts/vision_records::grant_access()
fn grant_access(env: Env, patient: Address, doctor: Address, ttl: u64) {
    patient.require_auth(); // Validated GDC...PATIENT_KEY_99X
    
    // Target Clinic: ${doctor}
    // Duration TTL: ${hours} Hours (${hours * 3600} Seconds)
    let grant = AccessGrant {
        granted_at: env.ledger().timestamp(),
        expires_at: env.ledger().timestamp() + ${hours * 3600},
        active: true,
    };
    
    env.storage().persistent().set(&(patient, doctor), &grant);
    env.events().publish(("access", "granted"), (patient, doctor));
}

// Transaction Status: ${statusStr}`;
    }
  }
}

/* ==========================================================================
   ZK Proof Simulator
   ========================================================================== */
function initZKSimulator() {
  const acuitySlider = document.getElementById('acuity-slider');
  const acuityVal = document.getElementById('acuity-val');
  const genZkBtn = document.getElementById('btn-gen-zk');
  const previewZkCode = document.getElementById('preview-zk-code');

  if (acuitySlider && acuityVal) {
    acuitySlider.addEventListener('input', (e) => {
      const val = e.target.value;
      acuityVal.textContent = `20/${val}`;
      updateZKPreview();
    });
  }

  if (genZkBtn) {
    genZkBtn.closest('form').addEventListener('submit', (e) => {
      e.preventDefault();
      genZkBtn.textContent = '🛡️ Generating Groth16 Proof...';

      setTimeout(() => {
        genZkBtn.textContent = '✅ Proof Verified Valid!';
        updateZKPreview(true);

        setTimeout(() => {
          genZkBtn.textContent = 'Generate Groth16 zk-SNARK';
        }, 2500);
      }, 800);
    });
  }

  function updateZKPreview(generated = false) {
    const score = acuitySlider ? acuitySlider.value : '20';
    const isValid = parseInt(score) <= 40;
    const proofHex = generated ? '0x98f21a007b82f10d9e4a8b71...' : '0xPREPARED_ZK_PROOF_BYTES';

    if (previewZkCode) {
      previewZkCode.textContent = `{
  "circuit": "contracts/zk_verifier::visual_acuity_proof",
  "patient_private_acuity": "20/${score}",
  "public_threshold": "Visual Acuity <= 20/40",
  "proof_bytes": "${proofHex}",
  "evaluation_result": ${isValid ? '"PASS_VERIFIED"' : '"FAIL_REQUIREMENT_NOT_MET"'},
  "status": "${generated ? 'ONCHAIN_VERIFIED' : 'READY_TO_SUBMIT'}",
  "patient_identity_revealed": false
}`;
    }
  }
}

/* ==========================================================================
   AI Oracle Rotation Simulator
   ========================================================================== */
function initAISimulator() {
  const aiStatusSelect = document.getElementById('select-ai-status');
  const testAiBtn = document.getElementById('btn-test-ai');
  const previewAiCode = document.getElementById('preview-ai-code');

  if (testAiBtn) {
    testAiBtn.closest('form').addEventListener('submit', (e) => {
      e.preventDefault();
      const status = aiStatusSelect ? aiStatusSelect.value : 'healthy';

      testAiBtn.textContent = '🤖 Evaluating Diagnostic Oracles...';

      setTimeout(() => {
        testAiBtn.textContent = 'Execute Diagnostic Check';

        if (status === 'timeout') {
          if (previewAiCode) {
            previewAiCode.textContent = `[AI_INTEGRATION] Primary Provider "AI_Vision_Alpha" TIMEOUT (500ms Exceeded).
[FAILOVER_TRIGGERED] Executing contracts/ai_integration::rotate_provider()
[PROVIDER_ROTATION] Degrading "AI_Vision_Alpha" Weight: 100 -> 0 (Status: Paused)
[SECONDARY_PROMOTED] Activated Secondary Oracle: "AI_Vision_Beta" (Weight: 90)
[DIAGNOSTIC_RESULT] Analysis Complete via Backup Node.
[EVENT_EMITTED] ProviderRotated(Primary: "AI_Vision_Beta", Reason: SLA_Timeout)`;
          }
        } else {
          if (previewAiCode) {
            previewAiCode.textContent = `[AI_INTEGRATION] Primary Provider Active: "AI_Vision_Alpha" (Weight: 100)
[ORACLE_CALL] Processing Retinal Scan CID: ipfs://QmX9z82...
[DIAGNOSTIC_RESULT] Diagnostics Confirmed: No Diabetic Retinopathy Detected.
[LATENCY] Response Time: 42ms (Within 100ms SLA Window)
[EVENT_EMITTED] ProviderStatusChecked(Active, Weight: 100)`;
          }
        }
      }, 600);
    });
  }
}

/* ==========================================================================
   FHIR v4 Converter Simulator
   ========================================================================== */
function initFHIRSimulator() {
  const fhirTypeSelect = document.getElementById('select-fhir-type');
  const convertFhirBtn = document.getElementById('btn-convert-fhir');
  const previewFhirCode = document.getElementById('preview-fhir-code');

  if (convertFhirBtn) {
    convertFhirBtn.closest('form').addEventListener('submit', (e) => {
      e.preventDefault();
      const type = fhirTypeSelect ? fhirTypeSelect.value : 'refraction';

      convertFhirBtn.textContent = '🏥 Mapping to FHIR v4 JSON...';

      setTimeout(() => {
        convertFhirBtn.textContent = 'Generate FHIR v4 Payload';

        if (type === 'iop') {
          if (previewFhirCode) {
            previewFhirCode.textContent = `{
  "resourceType": "Observation",
  "status": "final",
  "code": {
    "coding": [{
      "system": "http://loinc.org",
      "code": "56844-4",
      "display": "Intraocular pressure by Tonometry"
    }]
  },
  "subject": { "reference": "Patient/GDC...PATIENT_KEY_99X" },
  "valueQuantity": {
    "value": 14.5,
    "unit": "mmHg",
    "system": "http://unitsofmeasure.org"
  },
  "effectiveDateTime": "2026-08-06T23:45:00Z"
}`;
          }
        } else {
          if (previewFhirCode) {
            previewFhirCode.textContent = `{
  "resourceType": "DiagnosticReport",
  "status": "final",
  "code": {
    "coding": [{
      "system": "http://loinc.org",
      "code": "28886-0",
      "display": "Refraction examination"
    }]
  },
  "subject": { "reference": "Patient/GDC...PATIENT_KEY_99X" },
  "conclusion": "Normal refraction. Prescription: Right Eye -1.25 SPH, Left Eye -1.00 SPH",
  "effectiveDateTime": "2026-08-06T23:45:00Z"
}`;
          }
        }
      }, 500);
    });
  }
}

/* ==========================================================================
   Clinical Data Fetch Simulator
   ========================================================================== */
function initDataFetchSimulator() {
  const fetchBtn = document.getElementById('btn-fetch-data');
  const fetchIdle = document.getElementById('fetch-idle');
  const fetchPlaceholder = document.getElementById('fetch-placeholder');
  const fetchResult = document.getElementById('fetch-result-container');
  const fetchStatusLabel = document.getElementById('fetch-status-label');
  const fetchStatusIndicator = document.getElementById('fetch-status-indicator');

  if (fetchBtn) {
    fetchBtn.closest('form').addEventListener('submit', (e) => {
      e.preventDefault();
      // 1. Hide idle and result, show placeholder
      if(fetchIdle) fetchIdle.style.display = 'none';
      if(fetchResult) fetchResult.style.display = 'none';
      if(fetchPlaceholder) fetchPlaceholder.style.display = 'flex';
      
      fetchBtn.textContent = 'Fetching from IPFS...';
      fetchBtn.disabled = true;
      fetchBtn.style.opacity = '0.7';

      if(fetchStatusLabel) fetchStatusLabel.textContent = 'DATA_RETRIEVAL IN_PROGRESS';
      if(fetchStatusIndicator) fetchStatusIndicator.textContent = 'FETCHING_CID';

      // 2. Simulate network delay (e.g. 2.5 seconds)
      setTimeout(() => {
        // 3. Hide placeholder, show result
        if(fetchPlaceholder) fetchPlaceholder.style.display = 'none';
        if(fetchResult) fetchResult.style.display = 'block';

        fetchBtn.textContent = 'Fetch Clinical Data';
        fetchBtn.disabled = false;
        fetchBtn.style.opacity = '1';

        if(fetchStatusLabel) fetchStatusLabel.textContent = 'DATA_RETRIEVAL SUCCESS';
        if(fetchStatusIndicator) fetchStatusIndicator.textContent = 'DECRYPTED_PAYLOAD';
        
        if (typeof gsap !== 'undefined' && fetchResult) {
          gsap.fromTo(fetchResult, { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.4, ease: 'power2.out' });
        }
      }, 2500);
    });
  }
}

/* ==========================================================================
   <modal-dialog> Custom Web Component Base Component
   ========================================================================== */
class ModalDialog extends HTMLElement {
  static get observedAttributes() {
    return ['open', 'title', 'size', 'closable'];
  }

  constructor() {
    super();
    this.handleKeydown = this.handleKeydown.bind(this);
    this.handleOverlayClick = this.handleOverlayClick.bind(this);
  }

  connectedCallback() {
    this.render();
    this.setupListeners();
    this.updateVisibility();
  }

  disconnectedCallback() {
    document.removeEventListener('keydown', this.handleKeydown);
  }

  attributeChangedCallback(name, oldValue, newValue) {
    if (oldValue === newValue) return;
    if (name === 'open') {
      this.updateVisibility();
    } else if (name === 'title') {
      const titleEl = this.querySelector('.modal-dialog-title');
      if (titleEl) titleEl.textContent = newValue || '';
    } else if (name === 'size') {
      const cardEl = this.querySelector('.modal-dialog-card');
      if (cardEl) {
        cardEl.className = `modal-dialog-card size-${newValue || 'md'}`;
      }
    }
  }

  get open() {
    return this.hasAttribute('open');
  }

  set open(val) {
    if (val) {
      this.setAttribute('open', '');
    } else {
      this.removeAttribute('open');
    }
  }

  get title() {
    return this.getAttribute('title') || '';
  }

  set title(val) {
    this.setAttribute('title', val);
  }

  get size() {
    return this.getAttribute('size') || 'md';
  }

  set size(val) {
    this.setAttribute('size', val);
  }

  get closable() {
    return !this.hasAttribute('closable') || this.getAttribute('closable') !== 'false';
  }

  show() {
    this.open = true;
  }

  openModal() {
    this.open = true;
  }

  close() {
    this.open = false;
  }

  closeModal() {
    this.open = false;
  }

  toggle() {
    this.open = !this.open;
  }

  updateVisibility() {
    const overlay = this.querySelector('.modal-dialog-overlay');
    if (!overlay) return;

    if (this.open) {
      overlay.classList.add('active');
      document.body.style.overflow = 'hidden';
      document.addEventListener('keydown', this.handleKeydown);
      this.dispatchEvent(new CustomEvent('modal-open', { bubbles: true, composed: true }));
    } else {
      overlay.classList.remove('active');
      document.body.style.overflow = '';
      document.removeEventListener('keydown', this.handleKeydown);
      this.dispatchEvent(new CustomEvent('modal-close', { bubbles: true, composed: true }));
    }
  }

  handleKeydown(e) {
    if (e.key === 'Escape' && this.open && this.closable) {
      this.close();
    }
  }

  handleOverlayClick(e) {
    if (e.target.classList.contains('modal-dialog-overlay') && this.closable) {
      this.close();
    }
  }

  render() {
    if (this.querySelector('.modal-dialog-overlay')) return;

    const titleText = this.title;
    const sizeAttr = this.size;
    const isClosable = this.closable;

    const bodyContent = this.innerHTML;

    this.innerHTML = `
      <div class="modal-dialog-overlay" role="dialog" aria-modal="true" aria-label="${titleText}">
        <div class="modal-dialog-card size-${sizeAttr}">
          <div class="modal-dialog-header">
            <h3 class="modal-dialog-title">${titleText}</h3>
            ${isClosable ? `<button class="modal-dialog-close-btn" aria-label="Close modal">✕</button>` : ''}
          </div>
          <div class="modal-dialog-body">
            ${bodyContent}
          </div>
        </div>
      </div>
    `;
  }

  setupListeners() {
    const overlay = this.querySelector('.modal-dialog-overlay');
    const closeBtn = this.querySelector('.modal-dialog-close-btn');

    if (overlay) {
      overlay.addEventListener('click', this.handleOverlayClick);
    }

    if (closeBtn) {
      closeBtn.addEventListener('click', () => this.close());
    }
  }
}

if (!customElements.get('modal-dialog')) {
  customElements.define('modal-dialog', ModalDialog);
}

/* ==========================================================================
   Modal Base Logic (Connect Wallet & Custom <modal-dialog> Triggering)
   ========================================================================== */
function initModal() {
  const modalOverlay = document.getElementById('modal-overlay');
  const customModal = document.getElementById('connect-wallet-dialog');
  const btnConnect = document.getElementById('btn-connect-wallet');
  const btnClose = document.getElementById('modal-close-btn');

  function openModal() {
    if (customModal && typeof customModal.openModal === 'function') {
      customModal.openModal();
    } else if (modalOverlay) {
      modalOverlay.classList.add('active');
      document.body.style.overflow = 'hidden';
    }
  }

  function closeModal() {
    if (customModal && typeof customModal.closeModal === 'function') {
      customModal.closeModal();
    } else if (modalOverlay) {
      modalOverlay.classList.remove('active');
      document.body.style.overflow = '';
    }
  }

  if (btnConnect) {
    btnConnect.addEventListener('click', (e) => {
      e.preventDefault();
      openModal();
    });
  }

  if (btnClose) {
    btnClose.addEventListener('click', closeModal);
  }

  if (modalOverlay) {
    modalOverlay.addEventListener('click', (e) => {
      if (e.target === modalOverlay) {
        closeModal();
      }
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modalOverlay && modalOverlay.classList.contains('active')) {
      closeModal();
    }
  });
}
