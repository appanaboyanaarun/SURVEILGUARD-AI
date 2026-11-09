/**
 * SURVEILGUARD AI - Core Application Logic
 * Real-Time Suspicious Activity Detection, Video Processing, SMS Alerts, and Admin Monitoring
 */

// Application State
let currentView = 'dashboard';
let camerasList = [];
let eventsList = [];
let isProcessingVideo = false;

// Live Camera & Real Detection Engine State
let liveStream = null;
let liveDetectionInterval = null;
let isDetectionActive = false;
let currentSessionId = null;
let isRecordingEvidence = false;
let mediaRecorder = null;
let recordedChunks = [];
let lastDetectionResult = null;
let currentCameraFacing = 'environment';
let liveWs = null;

// =====================================================
// INITIALIZATION
// =====================================================
document.addEventListener('DOMContentLoaded', async () => {
  initClockHud();
  initNavigation();
  initAuth();
  initForms();

  // Check URL query parameters (e.g. ?event_id=EVT-0001 from SMS link)
  checkUrlParamsForDeepLink();

  // Initial Data Load
  try {
    await loadInitialData();
  } catch (err) {
    console.warn('Initial data load warning:', err);
  }
});

function initClockHud() {
  function updateTime() {
    const now = new Date();
    const timeStr = now.toLocaleTimeString();
    const hud = document.getElementById('liveClockText');
    if (hud) hud.textContent = timeStr;
    const hudTs = document.getElementById('hudTimestamp');
    if (hudTs) hudTs.textContent = timeStr;
  }
  updateTime();
  setInterval(updateTime, 1000);
}

// =====================================================
// AUTHENTICATION & SESSION MANAGEMENT
// =====================================================
function initAuth() {
  const token = Api.getToken();
  const user = Api.getUser();

  if (user) {
    updateUserUi(user);
  } else if (!token) {
    // Show login modal if not authenticated
    showAuthModal();
  }

  // Handle unauthorized event
  window.addEventListener('auth:unauthorized', () => {
    showAuthModal('Session expired. Please log in again.');
  });
}

function showAuthModal(errMsg = '') {
  const modal = document.getElementById('authModalBackdrop');
  if (modal) modal.style.display = 'flex';
  const errBox = document.getElementById('authErrorMessage');
  if (errBox) {
    if (errMsg) {
      errBox.textContent = errMsg;
      errBox.style.display = 'block';
    } else {
      errBox.style.display = 'none';
    }
  }
}

function hideAuthModal() {
  const modal = document.getElementById('authModalBackdrop');
  if (modal) modal.style.display = 'none';
}

function updateUserUi(user) {
  const nameEl = document.getElementById('sidebarUserName');
  const roleEl = document.getElementById('sidebarUserRole');
  const subEl = document.getElementById('sidebarUserSubtitle');
  if (nameEl) nameEl.textContent = user.full_name || user.username || 'Admin';
  if (roleEl) roleEl.textContent = (user.role || 'ADMIN').toUpperCase();
  if (subEl) subEl.textContent = user.role === 'admin' ? 'System Administrator' : 'Security Operator';
}

async function handleLogout() {
  if (confirm('Are you sure you want to log out?')) {
    if (isDetectionActive) {
      await handleStopLiveDetection();
    }
    await Api.logout();
    updateUserUi({ username: 'Guest', role: 'Viewer', full_name: 'Logged Out' });
    showAuthModal('You have been logged out.');
  }
}

// =====================================================
// NAVIGATION & VIEW SWITCHING
// =====================================================
function initNavigation() {
  document.querySelectorAll('.sidebar-nav .nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const targetView = item.getAttribute('data-view');
      if (targetView) switchView(targetView);
    });
  });
}

function toggleMobileSidebar() {
  const sb = document.getElementById('appSidebar');
  const backdrop = document.getElementById('sidebarBackdrop');
  if (sb) sb.classList.toggle('open');
  if (backdrop) backdrop.classList.toggle('active');
}

function switchView(viewName) {
  currentView = viewName;

  // Close mobile sidebar if open
  const sb = document.getElementById('appSidebar');
  const backdrop = document.getElementById('sidebarBackdrop');
  if (sb) sb.classList.remove('open');
  if (backdrop) backdrop.classList.remove('active');

  // Update nav tabs
  document.querySelectorAll('.sidebar-nav .nav-item').forEach(el => {
    if (el.getAttribute('data-view') === viewName) {
      el.classList.add('active');
    } else {
      el.classList.remove('active');
    }
  });

  // Switch visible section
  document.querySelectorAll('.view-section').forEach(sec => {
    sec.classList.remove('active');
  });
  const targetSection = document.getElementById(`view-${viewName}`);
  if (targetSection) {
    targetSection.classList.add('active');
  }

  // Trigger view data refresh
  if (viewName === 'dashboard') {
    loadDashboardData();
  } else if (viewName === 'events') {
    loadEventsTable();
  } else if (viewName === 'alerts') {
    loadAlertsQueue();
  } else if (viewName === 'cameras') {
    loadCamerasList();
  } else if (viewName === 'incidents') {
    refreshEmailDashboard();
  } else if (viewName === 'reports') {
    loadActivityReport();
  }
}

// =====================================================
// DEEP LINKING (Direct SMS Video Evidence Links)
// =====================================================
function checkUrlParamsForDeepLink() {
  const urlParams = new URLSearchParams(window.location.search);
  const eventId = urlParams.get('event_id');
  if (eventId) {
    setTimeout(() => {
      openEventReviewModal(eventId);
    }, 400);
  }
}

// =====================================================
// DATA LOADING
// =====================================================
async function loadInitialData() {
  await loadCamerasList();
  await loadDashboardData();
}

async function loadDashboardData() {
  try {
    const summary = await Api.getDashboardSummary();
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val !== undefined ? val : 0;
    };

    setVal('kpiTotalEvents', summary.total_events);
    setVal('kpiNormalEvents', summary.normal_events);
    setVal('kpiSuspiciousEvents', summary.suspicious_events);
    setVal('kpiHighAlerts', summary.high_priority_alerts);
    setVal('kpiActiveCameras', summary.cameras_active);
    setVal('kpiEmailAlerts', summary.email_alerts_sent || summary.suspicious_events || 0);

    // Update alert badges
    const alertBadge = document.getElementById('sidebarAlertBadge');
    if (alertBadge) {
      alertBadge.textContent = summary.suspicious_events;
      alertBadge.style.display = summary.suspicious_events > 0 ? 'inline-block' : 'none';
    }

    // Load Charts
    const chartsData = await Api.getDashboardCharts();
    if (window.ChartsManager) {
      window.ChartsManager.renderCharts(chartsData);
    }
  } catch (err) {
    console.error('Failed to load dashboard data:', err);
  }
}

// =====================================================
// GENUINE LIVE CAMERA & AI DETECTION PIPELINE
// =====================================================
async function handleStartLiveDetection() {
  const camSelect = document.getElementById('liveCameraSelect');
  const cameraId = camSelect ? camSelect.value : 'CAM-01';
  const facingSelect = document.getElementById('cameraDeviceSelect');
  const facingMode = facingSelect ? facingSelect.value : currentCameraFacing;

  try {
    updateLiveHudStatus('ANALYZING', 'Connecting to camera device...');

    // 1. Request Camera Permission & Stream
    const constraints = {
      video: {
        facingMode: facingMode,
        width: { ideal: 640 },
        height: { ideal: 480 },
      },
      audio: false,
    };

    liveStream = await navigator.mediaDevices.getUserMedia(constraints);
    const videoEl = document.getElementById('liveCameraVideo');
    videoEl.srcObject = liveStream;
    await videoEl.play();

    // 2. Start Detection Session on Backend
    try {
      const session = await Api.startDetectionSession(cameraId, navigator.userAgent);
      currentSessionId = session.session_id;
      const sBadge = document.getElementById('liveSessionBadge');
      const sText = document.getElementById('activeSessionIdText');
      if (sBadge && sText) {
        sText.textContent = currentSessionId;
        sBadge.style.display = 'inline-block';
      }
    } catch (e) {
      console.warn('Could not register detection session:', e);
      currentSessionId = `SES-LIVE-${Date.now().toString().slice(-4)}`;
    }

    // 3. Update UI Controls
    isDetectionActive = true;
    document.getElementById('cameraOffPlaceholder').style.display = 'none';
    document.getElementById('cameraHudOverlay').style.display = 'flex';
    document.getElementById('btnStartLiveDetection').style.display = 'none';
    document.getElementById('btnStopLiveDetection').style.display = 'inline-flex';
    document.getElementById('hudCameraTagText').textContent = `${cameraId} • LIVE`;

    const liveBadge = document.getElementById('sidebarLiveStatusBadge');
    if (liveBadge) liveBadge.style.display = 'inline-block';

    updateLiveHudStatus('NORMAL', 'Detection Active: No suspicious activity detected');

    // 4. Start Real Frame Analysis Loop (at ~2.5 FPS)
    startLiveInferenceLoop(cameraId);

  } catch (err) {
    console.error('Camera access failed:', err);
    updateLiveHudStatus('STANDBY', `Camera Error: ${err.message || 'Permission denied'}`);
    alert(`Could not start live detection: ${err.message || 'Camera permission denied or camera not available'}`);
  }
}

async function handleStopLiveDetection() {
  isDetectionActive = false;

  // Stop frame loop
  if (liveDetectionInterval) {
    clearInterval(liveDetectionInterval);
    liveDetectionInterval = null;
  }

  // Stop camera tracks
  if (liveStream) {
    liveStream.getTracks().forEach(t => t.stop());
    liveStream = null;
  }

  // Stop active session on backend
  if (currentSessionId && !currentSessionId.startsWith('SES-LIVE')) {
    try {
      await Api.stopDetectionSession(currentSessionId);
    } catch (e) {
      console.warn('Failed to stop backend session:', e);
    }
  }
  currentSessionId = null;

  // Reset UI
  document.getElementById('cameraOffPlaceholder').style.display = 'block';
  document.getElementById('cameraHudOverlay').style.display = 'none';
  document.getElementById('btnStartLiveDetection').style.display = 'inline-flex';
  document.getElementById('btnStopLiveDetection').style.display = 'none';
  
  const sBadge = document.getElementById('liveSessionBadge');
  if (sBadge) sBadge.style.display = 'none';
  const liveBadge = document.getElementById('sidebarLiveStatusBadge');
  if (liveBadge) liveBadge.style.display = 'none';

  // Clear canvas
  const canvas = document.getElementById('liveDetectionCanvas');
  if (canvas) {
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
  }

  updateLiveHudStatus('STANDBY', 'CAMERA OFF — Press Start to Begin Live Monitoring');
}

function getVideoRenderedRect(video) {
  const vWidth = video.videoWidth || 640;
  const vHeight = video.videoHeight || 480;
  const vAspect = vWidth / vHeight;
  const cWidth = video.clientWidth || 640;
  const cHeight = video.clientHeight || 480;
  const cAspect = cWidth / cHeight;

  let renderWidth, renderHeight, offsetX, offsetY;
  if (cAspect > vAspect) {
    // Pillarbox: black bars on left & right
    renderHeight = cHeight;
    renderWidth = renderHeight * vAspect;
    offsetX = (cWidth - renderWidth) / 2;
    offsetY = 0;
  } else {
    // Letterbox: black bars on top & bottom
    renderWidth = cWidth;
    renderHeight = renderWidth / vAspect;
    offsetX = 0;
    offsetY = (cHeight - renderHeight) / 2;
  }
  return { offsetX, offsetY, renderWidth, renderHeight, vWidth, vHeight };
}

function startLiveInferenceLoop(cameraId) {
  if (liveDetectionInterval) clearInterval(liveDetectionInterval);

  const video = document.getElementById('liveCameraVideo');
  const canvas = document.getElementById('liveDetectionCanvas');
  if (!video || !canvas) return;

  const captureCanvas = document.createElement('canvas');

  liveDetectionInterval = setInterval(async () => {
    if (!isDetectionActive || !liveStream || video.paused || video.ended) return;

    try {
      // Sync canvas display resolution to video client element
      if (canvas.width !== video.clientWidth || canvas.height !== video.clientHeight) {
        canvas.width = video.clientWidth || 640;
        canvas.height = video.clientHeight || 480;
      }

      // Preserve native aspect ratio when capturing frame for AI inference
      const vw = video.videoWidth || 640;
      const vh = video.videoHeight || 480;
      const maxDim = 640;
      const capScale = Math.min(maxDim / vw, maxDim / vh, 1.0);
      captureCanvas.width = Math.max(320, Math.round(vw * capScale));
      captureCanvas.height = Math.max(240, Math.round(vh * capScale));
      const capCtx = captureCanvas.getContext('2d');
      capCtx.drawImage(video, 0, 0, captureCanvas.width, captureCanvas.height);

      const blob = await new Promise(resolve => captureCanvas.toBlob(resolve, 'image/jpeg', 0.85));
      if (!blob) return;

      const fd = new FormData();
      fd.append('frame', blob, 'frame.jpg');
      fd.append('camera_id', cameraId);
      fd.append('location', 'Live Station');
      if (currentSessionId) fd.append('session_id', currentSessionId);

      // Call genuine detection API
      const result = await Api.detectLiveFrame(fd);
      lastDetectionResult = result;

      // Render genuine overlay on canvas with sub-pixel alignment
      renderDetectionOverlay(canvas, result, video);

      // Update metrics & HUD with real data
      updateLiveMetricsUi(result);

      // Handle Confirmed Suspicious Alert
      if (result.is_confirmed || (result.alert && result.status === 'SUSPICIOUS')) {
        handleConfirmedSuspiciousAlert(result);
      }

    } catch (err) {
      console.warn('Frame detection cycle error:', err);
      updateLiveHudStatus('DETECTION_SERVICE_ERROR', 'Detection Service Error: ' + (err.message || 'Network error'));
    }
  }, 400); // 2.5 frames per second
}

function renderDetectionOverlay(canvas, result, video) {
  const ctx = canvas.getContext('2d');
  const w = canvas.width;
  const h = canvas.height;

  ctx.clearRect(0, 0, w, h);

  const { offsetX, offsetY, renderWidth, renderHeight } = getVideoRenderedRect(video || document.getElementById('liveCameraVideo'));

  // 1. Draw Camera Configured Restricted Zone Polygon
  const activeCam = camerasList.find(c => c.camera_id === (result.camera_id || 'CAM-01'));
  let zoneCoords = null;
  if (activeCam && activeCam.restricted_zone_coords) {
    try {
      zoneCoords = typeof activeCam.restricted_zone_coords === 'string'
        ? JSON.parse(activeCam.restricted_zone_coords)
        : activeCam.restricted_zone_coords;
    } catch (e) {}
  }
  if (!zoneCoords || !Array.isArray(zoneCoords)) {
    // Default restricted zone (top-right sector)
    zoneCoords = [[0.55, 0.20], [0.95, 0.20], [0.95, 0.85], [0.55, 0.85]];
  }

  const isZoneBreached = result.breached_zones && result.breached_zones.length > 0;
  if (zoneCoords && zoneCoords.length >= 3) {
    ctx.beginPath();
    zoneCoords.forEach((pt, idx) => {
      const zx = offsetX + pt[0] * renderWidth;
      const zy = offsetY + pt[1] * renderHeight;
      if (idx === 0) ctx.moveTo(zx, zy);
      else ctx.lineTo(zx, zy);
    });
    ctx.closePath();
    ctx.fillStyle = isZoneBreached ? 'rgba(239, 68, 68, 0.24)' : 'rgba(59, 130, 246, 0.12)';
    ctx.fill();
    ctx.strokeStyle = isZoneBreached ? '#ef4444' : '#3b82f6';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Zone Badge Header
    const firstPt = zoneCoords[0];
    const lx = Math.max(offsetX, offsetX + firstPt[0] * renderWidth);
    const ly = Math.max(offsetY + 20, offsetY + firstPt[1] * renderHeight);
    ctx.fillStyle = isZoneBreached ? '#ef4444' : '#3b82f6';
    ctx.fillRect(lx, ly - 20, 130, 20);
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 10px JetBrains Mono, monospace';
    ctx.fillText(isZoneBreached ? 'ZONE BREACHED' : 'RESTRICTED ZONE', lx + 6, ly - 6);
  }

  // 2. Draw Genuine Detected Person Bounding Boxes
  if (result.boxes && result.boxes.length > 0) {
    result.boxes.forEach((box, idx) => {
      let bx, by, bw, bh;

      // Use normalized coordinates [0.0, 1.0] when available for pixel-perfect scaling
      if (result.normalized_boxes && result.normalized_boxes[idx]) {
        const nb = result.normalized_boxes[idx];
        bx = offsetX + nb[0] * renderWidth;
        by = offsetY + nb[1] * renderHeight;
        bw = nb[2] * renderWidth;
        bh = nb[3] * renderHeight;
      } else {
        const vEl = video || document.getElementById('liveCameraVideo');
        const fw = (vEl && vEl.videoWidth) ? vEl.videoWidth : 640;
        const fh = (vEl && vEl.videoHeight) ? vEl.videoHeight : 480;
        bx = offsetX + (box[0] / fw) * renderWidth;
        by = offsetY + (box[1] / fh) * renderHeight;
        bw = (box[2] / fw) * renderWidth;
        bh = (box[3] / fh) * renderHeight;
      }

      const boxColor = result.status === 'SUSPICIOUS' ? '#ef4444' : '#10b981';

      ctx.strokeStyle = boxColor;
      ctx.lineWidth = 2;
      ctx.strokeRect(bx, by, bw, bh);

      // Corner Accents for high-tech HUD look
      const corner = Math.min(12, bw / 3, bh / 3);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 3;
      // Top-Left
      ctx.beginPath(); ctx.moveTo(bx, by + corner); ctx.lineTo(bx, by); ctx.lineTo(bx + corner, by); ctx.stroke();
      // Top-Right
      ctx.beginPath(); ctx.moveTo(bx + bw - corner, by); ctx.lineTo(bx + bw, by); ctx.lineTo(bx + bw, by + corner); ctx.stroke();
      // Bottom-Left
      ctx.beginPath(); ctx.moveTo(bx, by + bh - corner); ctx.lineTo(bx, by + bh); ctx.lineTo(bx + corner, by + bh); ctx.stroke();
      // Bottom-Right
      ctx.beginPath(); ctx.moveTo(bx + bw - corner, by + bh); ctx.lineTo(bx + bw, by + bh); ctx.lineTo(bx + bw, by + bh - corner); ctx.stroke();

      // Person Confidence Label
      const confVal = (result.confidences && result.confidences[idx] !== undefined)
        ? result.confidences[idx]
        : (result.person_confidence || result.confidence || 0.85);
      const confPct = Math.round(confVal * 100);

      const labelY = Math.max(offsetY + 20, by);
      ctx.fillStyle = boxColor;
      ctx.fillRect(bx, labelY - 20, 115, 20);
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 10.5px JetBrains Mono, monospace';
      ctx.fillText(`PERSON ${confPct}%`, bx + 6, labelY - 6);
    });
  }
}

function updateLiveMetricsUi(result) {
  const pCount = document.getElementById('liveMetricPersonCount');
  const mScore = document.getElementById('liveMetricMotionScore');
  const aScore = document.getElementById('liveMetricAnomalyScore');
  const rLevel = document.getElementById('liveMetricRiskLevel');

  if (pCount) pCount.textContent = result.person_count !== undefined ? result.person_count : 0;
  if (mScore) mScore.textContent = `${Math.round((result.motion_score || 0) * 100)}%`;
  if (aScore) aScore.textContent = (result.anomaly_score || 0).toFixed(2);
  if (rLevel) {
    rLevel.textContent = result.risk_priority || 'LOW';
    rLevel.style.color = result.status === 'SUSPICIOUS' ? 'var(--danger-red)' : 'var(--success-green)';
  }

  const hudStats = document.getElementById('hudDetectionStats');
  if (hudStats) {
    hudStats.textContent = `PEOPLE: ${result.person_count} | MOTION: ${(result.motion_score || 0).toFixed(2)} | ANOMALY: ${(result.anomaly_score || 0).toFixed(2)}`;
  }

  // Update Status Banner with strictly separated UI states
  if (isRecordingEvidence) {
    updateLiveHudStatus(
      'RECORDING_EVIDENCE',
      'RECORDING EVIDENCE — Auto-capturing incident video clip for security audit'
    );
  } else if (result.status === 'SUSPICIOUS') {
    const confPct = Math.round((result.confidence || 0.85) * 100);
    updateLiveHudStatus(
      'SUSPICIOUS_ACTIVITY_DETECTED',
      `SUSPICIOUS ACTIVITY DETECTED — ${result.activity_type} (${result.risk_priority} Risk)`
    );
  } else if (result.breached_zones && result.breached_zones.length > 0) {
    updateLiveHudStatus(
      'SECURITY_RULE_TRIGGERED',
      `SECURITY RULE TRIGGERED — Zone breach observed (${result.breached_zones.join(', ')}), confirming...`
    );
  } else if (result.person_count > 0) {
    const confPct = Math.round((result.confidence || 0.85) * 100);
    updateLiveHudStatus(
      'PERSON_DETECTED',
      `PERSON DETECTED (${result.person_count} in view, ${confPct}% conf) • NO SUSPICIOUS ACTIVITY DETECTED`
    );
  } else {
    updateLiveHudStatus(
      'NO_PERSON_DETECTED',
      'DETECTION ACTIVE — Monitored Area Clear • NO PERSON DETECTED'
    );
  }
}

function updateLiveHudStatus(state, message) {
  const banner = document.getElementById('liveDetectionStatusHud');
  const title = document.getElementById('liveStatusTitle');
  const icon = document.getElementById('liveStatusIcon');
  if (!banner || !title) return;

  banner.className = 'detection-status-hud';
  title.textContent = message;

  if (state === 'SUSPICIOUS_ACTIVITY_DETECTED' || state === 'SUSPICIOUS') {
    banner.classList.add('suspicious');
    if (icon) icon.className = 'fas fa-triangle-exclamation';
  } else if (state === 'SECURITY_RULE_TRIGGERED' || state === 'CONFIRMING_INCIDENT') {
    banner.classList.add('warning');
    if (icon) icon.className = 'fas fa-bell';
  } else if (state === 'RECORDING_EVIDENCE') {
    banner.classList.add('recording');
    if (icon) icon.className = 'fas fa-circle-dot fa-fade';
  } else if (state === 'EVIDENCE_SAVED' || state === 'EMAIL_SENT') {
    banner.classList.add('normal');
    if (icon) icon.className = 'fas fa-paper-plane';
  } else if (state === 'SMS_FAILED' || state === 'CAMERA_ERROR' || state === 'DETECTION_SERVICE_ERROR') {
    banner.classList.add('error');
    if (icon) icon.className = 'fas fa-circle-xmark';
  } else if (state === 'PERSON_DETECTED') {
    banner.classList.add('normal');
    if (icon) icon.className = 'fas fa-user-check';
  } else if (state === 'NO_PERSON_DETECTED' || state === 'NORMAL' || state === 'NO_SUSPICIOUS_ACTIVITY_DETECTED') {
    banner.classList.add('normal');
    if (icon) icon.className = 'fas fa-circle-check';
  } else if (state === 'ANALYZING' || state === 'DETECTION_ACTIVE') {
    banner.classList.add('analyzing');
    if (icon) icon.className = 'fas fa-microchip fa-spin';
  } else if (state === 'CAMERA_READY') {
    banner.classList.add('standby');
    if (icon) icon.className = 'fas fa-camera';
  } else {
    banner.classList.add('standby');
    if (icon) icon.className = 'fas fa-power-off';
  }
}

function handleConfirmedSuspiciousAlert(result) {
  console.log('[ALERT CONFIRMED]', result);

  // Trigger short evidence recording clip automatically (5-8s)
  if (!isRecordingEvidence && liveStream) {
    const eventId = result.alert ? result.alert.event_id : null;
    const smsSent = result.alert ? result.alert.sms_dispatched : false;
    recordEvidenceClip(eventId, smsSent);
  }

  // Refresh dashboard metrics in background
  loadDashboardData();
}

function recordEvidenceClip(eventId, emailDispatched) {
  if (!liveStream || isRecordingEvidence) return;

  isRecordingEvidence = true;
  recordedChunks = [];

  const recIndicator = document.getElementById('hudRecIndicator');
  if (recIndicator) recIndicator.style.display = 'inline-flex';

  updateLiveHudStatus('RECORDING_EVIDENCE', 'RECORDING EVIDENCE — Capturing incident clip for secure archive...');

  try {
    let options = { mimeType: 'video/webm;codecs=vp8,opus' };
    if (!MediaRecorder.isTypeSupported(options.mimeType)) {
      options = { mimeType: 'video/webm' };
    }
    mediaRecorder = new MediaRecorder(liveStream, options);

    mediaRecorder.ondataavailable = (e) => {
      if (e.data && e.data.size > 0) {
        recordedChunks.push(e.data);
      }
    };

    mediaRecorder.onstop = async () => {
      if (recIndicator) recIndicator.style.display = 'none';
      isRecordingEvidence = false;

      if (recordedChunks.length === 0) return;

      const videoBlob = new Blob(recordedChunks, { type: 'video/webm' });
      const fd = new FormData();
      fd.append('video_file', videoBlob, `evidence_${eventId || Date.now()}.webm`);
      if (eventId) fd.append('event_id', eventId);
      if (currentSessionId) fd.append('session_id', currentSessionId);
      fd.append('duration_seconds', '8.0');

      try {
        const saved = await Api.saveEvidenceClip(fd);
        console.log('[EVIDENCE SAVED]', saved);
        if (smsDispatched) {
          updateLiveHudStatus('SMS_SENT', `EVIDENCE SAVED • SMS SENT to Admin with secure video link (Event ${eventId || 'NEW'})`);
        } else {
          updateLiveHudStatus('EVIDENCE_SAVED', `EVIDENCE SAVED — Clip archived securely (Event: ${eventId || 'NEW'})`);
        }
      } catch (e) {
        console.error('Failed to save evidence clip:', e);
        updateLiveHudStatus('EVIDENCE_SAVED', `Evidence recorded locally (Upload failed: ${e.message || 'Network error'})`);
      }
    };

    mediaRecorder.start(500);

    // Stop after 8 seconds
    setTimeout(() => {
      if (mediaRecorder && mediaRecorder.state === 'recording') {
        mediaRecorder.stop();
      }
    }, 8000);

  } catch (err) {
    console.error('MediaRecorder initialization failed:', err);
    isRecordingEvidence = false;
    if (recIndicator) recIndicator.style.display = 'none';
  }
}

// =====================================================
// VIDEO FILE INGESTION & PROCESSING
// =====================================================
function selectIngestionMode(mode) {
  document.querySelectorAll('.ingestion-tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.ingestion-tab-content').forEach(c => c.classList.remove('active'));

  const btn = document.getElementById(`tabBtn${mode.charAt(0).toUpperCase() + mode.slice(1)}`);
  const content = document.getElementById(`mode-${mode}`);
  if (btn) btn.classList.add('active');
  if (content) content.classList.add('active');
}

function setNowTimestamp() {
  const now = new Date();
  now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
  const formatted = now.toISOString().slice(0, 16);
  const input = document.getElementById('customTimestampInput');
  if (input) input.value = formatted;
}

function pickScenario(filename, camId, timestamp, el) {
  document.querySelectorAll('.scenario-card').forEach(c => c.classList.remove('active'));
  if (el) el.classList.add('active');

  const fileInput = document.getElementById('selectedScenarioFile');
  if (fileInput) fileInput.value = filename;

  const camSelect = document.getElementById('videoCameraSelect');
  if (camSelect) camSelect.value = camId;

  const tsInput = document.getElementById('customTimestampInput');
  if (tsInput) tsInput.value = timestamp;
}

async function handleScenarioProcessing() {
  const scenarioFile = document.getElementById('selectedScenarioFile').value;
  const camSelect = document.getElementById('videoCameraSelect');
  const cameraId = camSelect ? camSelect.value : 'CAM-03';
  const timestamp = document.getElementById('customTimestampInput').value;

  const fd = new FormData();
  fd.append('camera_id', cameraId);
  fd.append('sample_video_name', scenarioFile);
  if (timestamp) fd.append('custom_timestamp', timestamp);

  await executeVideoProcessing(fd);
}

async function executeVideoProcessing(formData) {
  const progPanel = document.getElementById('processingProgressPanel');
  const resCard = document.getElementById('processingResultCard');
  const term = document.getElementById('processingLogTerminal');
  const pBar = document.getElementById('processingProgressBar');
  const pText = document.getElementById('processingPctText');

  if (progPanel) progPanel.style.display = 'block';
  if (resCard) resCard.style.display = 'none';
  if (term) term.textContent = '>> Initializing OpenCV Computer Vision pipeline...\n';

  if (pBar) pBar.style.width = '20%';
  if (pText) pText.textContent = 'Analyzing Video Frames';

  try {
    const result = await Api.processVideo(formData);

    if (pBar) pBar.style.width = '100%';
    if (pText) pText.textContent = 'Processing Complete (100%)';
    if (term) {
      term.textContent += `>> Tracking person bounding boxes & restricted zone collisions...\n`;
      term.textContent += `>> Extracted Metadata: People=${result.person_count}, Activity=${result.activity_type}, Duration=${result.event_duration_formatted}\n`;
      term.textContent += `>> Isolation Forest ML Anomaly Score: ${result.anomaly_score.toFixed(3)}\n`;
      term.textContent += `>> Verdict: ${result.status} (${result.risk_priority} PRIORITY)\n`;
    }

    // Display Result Card
    setTimeout(() => {
      displayProcessingResult(result);
    }, 600);

    // Refresh Dashboard
    loadDashboardData();

  } catch (err) {
    if (term) term.textContent += `>> ERROR: ${err.message || 'Processing failed'}\n`;
    alert(`Video processing failed: ${err.message}`);
  }
}

function displayProcessingResult(res) {
  const resCard = document.getElementById('processingResultCard');
  if (!resCard) return;

  document.getElementById('resEventId').textContent = res.event_id;
  document.getElementById('resCameraId').textContent = `${res.camera_id} (${res.location})`;
  document.getElementById('resTimestamp').textContent = new Date(res.timestamp).toLocaleString();
  document.getElementById('resPersonCount').textContent = res.person_count;
  document.getElementById('resActivity').textContent = res.activity_type;
  document.getElementById('resDuration').textContent = res.event_duration_formatted;
  document.getElementById('resMotion').textContent = res.motion_level;
  document.getElementById('resRestricted').textContent = res.restricted_area === 1 ? 'YES (Zone Breached)' : 'NO';
  document.getElementById('resAnomalyScore').textContent = res.anomaly_score.toFixed(3);

  const statusBadge = document.getElementById('resStatus');
  statusBadge.className = res.status === 'SUSPICIOUS' ? 'badge badge-suspicious' : 'badge badge-normal';
  statusBadge.textContent = res.status;

  const priorityBadge = document.getElementById('resPriority');
  priorityBadge.className = `badge badge-priority-${res.risk_priority.toLowerCase()}`;
  priorityBadge.textContent = `${res.risk_priority} RISK`;

  const thumbImg = document.getElementById('resThumbnailImg');
  if (thumbImg && res.thumbnail_path) {
    thumbImg.src = res.thumbnail_path;
  }

  const reasonsList = document.getElementById('resReasonsList');
  reasonsList.innerHTML = '';
  if (res.anomaly_reasons) {
    res.anomaly_reasons.split(';').forEach(r => {
      if (r.trim()) {
        const li = document.createElement('li');
        li.textContent = r.trim();
        reasonsList.appendChild(li);
      }
    });
  } else {
    const li = document.createElement('li');
    li.textContent = 'Standard routine activity parameters verified.';
    reasonsList.appendChild(li);
  }

  const reviewBtn = document.getElementById('resReviewBtn');
  if (reviewBtn) {
    reviewBtn.onclick = () => openEventReviewModal(res.event_id);
  }

  resCard.style.display = 'block';
}

// =====================================================
// EVENTS TABLE & SUSPICIOUS ALERTS QUEUE
// =====================================================
async function loadEventsTable() {
  const tbody = document.getElementById('eventsTableBody');
  if (!tbody) return;

  tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding:20px; color:var(--text-dim);">Loading events...</td></tr>';

  try {
    const search = document.getElementById('searchInput')?.value || '';
    const camera_id = document.getElementById('filterCamera')?.value || '';
    const status = document.getElementById('filterStatus')?.value || '';
    const risk_priority = document.getElementById('filterPriority')?.value || '';

    const events = await Api.getEvents({ search, camera_id, status, risk_priority });
    eventsList = events;

    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; padding:24px; color:var(--text-dim);">No events match the current filter criteria.</td></tr>';
      return;
    }

    tbody.innerHTML = events.map(e => `
      <tr>
        <td><strong style="font-family:var(--font-mono); color:var(--primary-blue);">${e.event_id}</strong></td>
        <td><strong>${e.camera_id}</strong> <br><small style="color:var(--text-dim);">${e.location}</small></td>
        <td style="font-size:12px;">${new Date(e.timestamp).toLocaleString()}</td>
        <td>${e.person_count}</td>
        <td>${e.activity_type}</td>
        <td><small style="font-weight:600;">${e.admin_name || 'Admin'}</small></td>
        <td><span class="badge ${e.status === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-normal'}">${e.status}</span></td>
        <td><span class="badge badge-priority-${(e.risk_priority || 'LOW').toLowerCase()}">${e.risk_priority || 'LOW'}</span></td>
        <td>
          <button class="btn btn-secondary" style="padding:4px 8px; font-size:11px;" onclick="openEventReviewModal('${e.event_id}')">
            <i class="fas fa-eye"></i> Details
          </button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="9" style="color:var(--danger-red); text-align:center;">Failed to load events: ${err.message}</td></tr>`;
  }
}

async function loadAlertsQueue() {
  const container = document.getElementById('alertsQueueContainer');
  if (!container) return;

  container.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-dim);">Loading suspicious alerts queue...</div>';

  try {
    const alerts = await Api.getAlerts();

    if (alerts.length === 0) {
      container.innerHTML = `
        <div style="text-align:center; padding:40px 20px; color:var(--text-dim);">
          <i class="fas fa-shield-check" style="font-size:36px; color:var(--success-green); margin-bottom:10px; display:block;"></i>
          <h3 style="color:var(--text-primary); font-size:16px;">All Clear</h3>
          <p style="font-size:13px;">No unreviewed suspicious events requiring immediate attention.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = alerts.map(a => `
      <div class="alert-card" style="border-left: 4px solid var(--danger-red); background:#fff; border-radius:var(--radius-md); padding:16px; margin-bottom:12px; border:1px solid var(--border-light); display:flex; gap:16px; align-items:center; flex-wrap:wrap;">
        <img src="${a.thumbnail_path || '/thumbnails/placeholder.jpg'}" style="width:100px; height:65px; object-fit:cover; border-radius:var(--radius-sm);" onerror="this.src='/thumbnails/placeholder.jpg'" />
        <div style="flex:1; min-width:220px;">
          <div style="display:flex; gap:8px; align-items:center; margin-bottom:4px;">
            <span style="font-family:var(--font-mono); font-weight:700; color:var(--danger-red);">${a.event_id}</span>
            <span class="badge badge-priority-high">${a.risk_priority} RISK</span>
            <span style="font-size:11px; color:var(--text-dim);">${new Date(a.timestamp).toLocaleString()}</span>
          </div>
          <h4 style="font-size:14px; font-weight:700; color:var(--text-primary); margin-bottom:2px;">${a.activity_type} on ${a.camera_id}</h4>
          <p style="font-size:12px; color:var(--text-muted);">${a.anomaly_reasons || 'ML Anomaly score threshold exceeded'}</p>
        </div>
        <div>
          <button class="btn btn-primary" onclick="openEventReviewModal('${a.event_id}')">
            <i class="fas fa-clipboard-check"></i> Review Threat
          </button>
        </div>
      </div>
    `).join('');

  } catch (err) {
    container.innerHTML = `<div style="color:var(--danger-red);">Failed to load alerts: ${err.message}</div>`;
  }
}

// =====================================================
// EVENT DETAIL & EVIDENCE VIDEO MODAL
// =====================================================
async function openEventReviewModal(eventId) {
  const modal = document.getElementById('reviewModalBackdrop');
  if (!modal) return;

  try {
    const event = await Api.getEventById(eventId);

    document.getElementById('modalEventId').textContent = event.event_id;
    document.getElementById('modalCamera').textContent = `${event.camera_id} (${event.location})`;
    document.getElementById('modalTimestamp').textContent = new Date(event.timestamp).toLocaleString();
    document.getElementById('modalPersonCount').textContent = event.person_count;
    document.getElementById('modalActivity').textContent = event.activity_type;
    document.getElementById('modalMotion').textContent = event.motion_level;
    document.getElementById('modalRestricted').textContent = event.restricted_area === 1 ? 'YES (Breached)' : 'NO';
    document.getElementById('modalAnomalyScore').textContent = event.anomaly_score.toFixed(3);

    // Update Email Dispatch Badge
    const emailBadge = document.getElementById('modalEmailStatusBadge');
    const emailDetails = document.getElementById('modalEmailDetails');
    const emailRawStatus = (event.email_status || 'NONE').toUpperCase();

    let badgeClass = 'badge-normal';
    let badgeLabel = emailRawStatus;

    if (emailRawStatus === 'NOT_CONFIGURED') {
      badgeClass = 'badge-priority-low';
      badgeLabel = 'EMAIL NOT CONFIGURED';
    } else if (emailRawStatus === 'SENT') {
      badgeClass = 'badge-success';
      badgeLabel = 'SENT (SMTP Accepted)';
    } else if (emailRawStatus === 'DELIVERED') {
      badgeClass = 'badge-success';
      badgeLabel = 'DELIVERED';
    } else if (emailRawStatus === 'PENDING' || emailRawStatus === 'QUEUED') {
      badgeClass = 'badge-priority-medium';
      badgeLabel = 'DISPATCH IN PROGRESS...';
    } else if (emailRawStatus === 'FAILED') {
      badgeClass = 'badge-danger';
      badgeLabel = 'DISPATCH FAILED';
    } else if (emailRawStatus === 'DUPLICATE_SKIPPED') {
      badgeClass = 'badge-normal';
      badgeLabel = 'SKIPPED (Duplicate)';
    }

    if (emailBadge) {
      emailBadge.className = `badge ${badgeClass}`;
      emailBadge.textContent = badgeLabel;
    }
    if (emailDetails) {
      if (event.email_sent_at) {
        emailDetails.textContent = `Sent at: ${new Date(event.email_sent_at).toLocaleTimeString()}`;
      } else if (emailRawStatus === 'NOT_CONFIGURED') {
        emailDetails.textContent = 'SMTP not configured — no email sent';
      } else if (emailRawStatus === 'DUPLICATE_SKIPPED') {
        emailDetails.textContent = 'Already sent for this incident';
      } else {
        emailDetails.textContent = '';
      }
    }

    // Thumbnail / Video
    const thumbImg = document.getElementById('modalThumbnail');
    const videoEl = document.getElementById('modalEvidenceVideoPlayer');
    const evStatus = document.getElementById('modalEvidenceStatusText');
    const evDuration = document.getElementById('modalEvidenceDuration');

    // Reset video player state
    if (videoEl) {
      videoEl.pause();
      videoEl.src = '';
      videoEl.style.display = 'none';
      videoEl.onerror = null;
      videoEl.onloadeddata = null;
    }

    // Always show snapshot thumbnail first
    if (thumbImg) {
      if (event.thumbnail_path) {
        thumbImg.src = event.thumbnail_path;
        thumbImg.style.display = 'block';
      } else {
        thumbImg.style.display = 'none';
      }
    }

    // Check secure video stream if evidence exists
    const targetVideoRef = event.evidence_video_id || event.event_id;
    if (videoEl && targetVideoRef) {
      try {
        if (evStatus) evStatus.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking evidence video...';
        const secureUrlData = await Api.getSecureVideoUrl(targetVideoRef);

        if (secureUrlData && secureUrlData.available && secureUrlData.secure_url) {
          if (evStatus) evStatus.innerHTML = '<i class="fas fa-video" style="color:var(--success-green);"></i> Evidence Video Ready';
          if (evDuration && event.event_duration_formatted) {
            evDuration.textContent = `Duration: ${event.event_duration_formatted}`;
          }

          videoEl.src = secureUrlData.secure_url;
          videoEl.style.display = 'block';
          if (thumbImg) thumbImg.style.display = 'none';

          videoEl.onerror = () => {
            console.warn('[Evidence] Video stream failed to load. Falling back to snapshot.');
            videoEl.style.display = 'none';
            if (thumbImg && event.thumbnail_path) thumbImg.style.display = 'block';
            if (evStatus) evStatus.innerHTML = '<i class="fas fa-image" style="color:var(--warning-amber);"></i> Stream unavailable (Snapshot displayed)';
          };
        } else {
          // Video file not available on storage
          videoEl.style.display = 'none';
          if (thumbImg && event.thumbnail_path) thumbImg.style.display = 'block';
          if (evStatus) {
            evStatus.innerHTML = '<i class="fas fa-camera" style="color:var(--primary-blue);"></i> Evidence Snapshot View (Video clip not recorded or in progress)';
          }
          if (evDuration) evDuration.textContent = '';
        }
      } catch (e) {
        videoEl.style.display = 'none';
        if (thumbImg && event.thumbnail_path) thumbImg.style.display = 'block';
        if (evStatus) evStatus.innerHTML = '<i class="fas fa-image"></i> Incident Snapshot (Evidence video stream unavailable)';
        if (evDuration) evDuration.textContent = '';
      }
    } else {
      if (evStatus) evStatus.innerHTML = '<i class="fas fa-camera"></i> Incident Snapshot';
      if (evDuration) evDuration.textContent = '';
    }

    // Reasons
    const reasonsList = document.getElementById('modalReasonsList');
    reasonsList.innerHTML = '';
    if (event.anomaly_reasons) {
      event.anomaly_reasons.split(';').forEach(r => {
        if (r.trim()) {
          const li = document.createElement('li');
          li.textContent = r.trim();
          reasonsList.appendChild(li);
        }
      });
    } else {
      const li = document.createElement('li');
      li.textContent = 'Standard routine surveillance verification.';
      reasonsList.appendChild(li);
    }

    // Previous Reviews Audit
    const prevRevContainer = document.getElementById('modalPreviousReviews');
    if (event.reviews && event.reviews.length > 0) {
      prevRevContainer.innerHTML = event.reviews.map(r => `
        <div style="background:#f1f5f9; padding:8px 10px; border-radius:4px; margin-bottom:6px; font-size:11px;">
          <strong>${r.reviewed_by}</strong> marked as <span class="badge ${r.review_status === 'CONFIRMED_SUSPICIOUS' ? 'badge-suspicious' : 'badge-normal'}">${r.review_status}</span> on ${new Date(r.reviewed_at).toLocaleString()}
          ${r.annotation ? `<div style="color:var(--text-muted); margin-top:2px;">"${r.annotation}"</div>` : ''}
        </div>
      `).join('');
    } else {
      prevRevContainer.innerHTML = '<div style="font-size:11px; color:var(--text-dim);">No human reviews recorded yet.</div>';
    }

    modal.style.display = 'flex';

  } catch (err) {
    alert(`Could not load event ${eventId}: ${err.message}`);
  }
}

function closeReviewModal() {
  const modal = document.getElementById('reviewModalBackdrop');
  if (modal) modal.style.display = 'none';
  const videoEl = document.getElementById('modalEvidenceVideoPlayer');
  if (videoEl) {
    videoEl.pause();
    videoEl.src = '';
  }
}

// =====================================================
// REPORTS & COMPLIANCE EXPORT
// =====================================================
function handleReportPeriodChange() {
  const period = document.getElementById('reportPeriodSelect').value;
  const customInputs = document.getElementById('customDateRangeInputs');
  if (customInputs) {
    customInputs.style.display = period === 'custom' ? 'flex' : 'none';
  }
}

async function loadActivityReport() {
  const period = document.getElementById('reportPeriodSelect')?.value || 'daily';
  const startDate = document.getElementById('reportStartDate')?.value || '';
  const endDate = document.getElementById('reportEndDate')?.value || '';

  const summaryBox = document.getElementById('reportSummaryContainer');
  const tbody = document.getElementById('reportEventsTableBody');

  try {
    const report = await Api.getActivityReport({
      period,
      start_date: startDate,
      end_date: endDate
    });

    if (summaryBox) summaryBox.style.display = 'block';

    document.getElementById('repTotal').textContent = report.total_events;
    document.getElementById('repNormal').textContent = report.normal_events;
    document.getElementById('repSuspicious').textContent = report.suspicious_events;
    document.getElementById('repEmail').textContent = report.email_alerts_dispatched || report.suspicious_events || 0;

    if (tbody) {
      tbody.innerHTML = report.events.map(e => `
        <tr>
          <td><strong style="font-family:var(--font-mono);">${e.event_id}</strong></td>
          <td style="font-size:11px;">${new Date(e.timestamp).toLocaleString()}</td>
          <td>${e.camera_id}</td>
          <td>${e.location}</td>
          <td>${e.activity_type}</td>
          <td><span class="badge ${e.status === 'SUSPICIOUS' ? 'badge-suspicious' : 'badge-normal'}">${e.status}</span></td>
          <td><span class="badge badge-priority-${(e.risk_priority || 'LOW').toLowerCase()}">${e.risk_priority || 'LOW'}</span></td>
          <td><small style="font-weight:700;">${e.email_status || 'NONE'}</small></td>
        </tr>
      `).join('');
    }

  } catch (err) {
    console.error('Failed to load report:', err);
  }
}

function handleDownloadReportCSV() {
  const period = document.getElementById('reportPeriodSelect')?.value || 'daily';
  const startDate = document.getElementById('reportStartDate')?.value || '';
  const endDate = document.getElementById('reportEndDate')?.value || '';

  const downloadUrl = Api.getReportCSVDownloadUrl(period, startDate, endDate);
  window.open(downloadUrl, '_blank');
}

// =====================================================
// EMAIL NOTIFICATION CENTER
// =====================================================
async function loadEmailProviderStatus() {
  const pill = document.getElementById('emailGatewayPill');
  const nameEl = document.getElementById('emailProviderName');
  const modeEl = document.getElementById('emailProviderMode');
  const fromEl = document.getElementById('emailFromAddress');
  const notesEl = document.getElementById('emailProviderNotes');

  try {
    const status = await Api.getEmailStatus();
    if (nameEl) nameEl.textContent = (status.provider || 'UNKNOWN').toUpperCase();
    if (modeEl) modeEl.textContent = `(${status.mode || 'UNCONFIGURED'})`;
    if (fromEl) fromEl.textContent = status.from || 'NOT SET';

    if (pill) {
      if (status.enabled === false) {
        pill.className = 'badge badge-priority-medium';
        pill.textContent = 'EMAIL DISABLED';
      } else if (!status.configured) {
        pill.className = 'badge badge-danger';
        pill.textContent = 'NOT CONFIGURED';
      } else if (status.provider === 'apps_script') {
        pill.className = 'badge badge-success';
        pill.style.background = '';
        pill.style.color = '';
        pill.style.borderColor = '';
        pill.textContent = 'APPS SCRIPT READY';
      } else {
        pill.className = 'badge badge-success';
        pill.style.background = '';
        pill.style.color = '';
        pill.style.borderColor = '';
        pill.textContent = `${(status.provider || 'EMAIL').toUpperCase()} READY`;
      }
    }

    if (modeEl) {
      modeEl.textContent = `(${status.mode || 'UNCONFIGURED'})`;
      if (status.mode === 'ACTIVE') {
        modeEl.style.color = 'var(--success-green)';
      } else {
        modeEl.style.color = 'var(--warning-amber)';
      }
    }

    if (notesEl) {
      if (status.issues && status.issues.length > 0) {
        notesEl.innerHTML = `<span style="color:var(--danger-red); font-weight:600;"><i class="fas fa-triangle-exclamation"></i> Action required:</span> ${status.issues.join('; ')}`;
      } else if (status.configured) {
        notesEl.innerHTML = `<span style="color:var(--success-green);"><i class="fas fa-circle-check"></i> Google Apps Script Web App active.</span> Alert requests are dispatched via HTTPS POST to Gmail MailApp for ${status.active_recipients_count || status.recipients_count || 0} recipient(s).`;
      } else {
        notesEl.innerHTML = `<span style="color:var(--warning-amber);"><i class="fas fa-info-circle"></i> Google Apps Script not configured.</span> Set <code>APPS_SCRIPT_WEB_APP_URL</code> and <code>APPS_SCRIPT_WEBHOOK_SECRET</code> in your <code>.env</code> file.`;
      }
    }
  } catch (err) {
    if (pill) {
      pill.className = 'badge badge-danger';
      pill.textContent = 'STATUS ERROR';
    }
    if (notesEl) notesEl.textContent = `Could not reach email status endpoint: ${err.message}`;
  }
}

async function handleSendTestEmail() {
  const statusBox = document.getElementById('emailTestStatus');
  if (statusBox) {
    statusBox.style.display = 'block';
    statusBox.className = 'detection-status-hud analyzing';
    statusBox.textContent = 'Contacting Google Apps Script HTTP API and dispatching test email...';
  }

  const emailInput = document.getElementById('testEmailInput');
  const customEmail = emailInput ? emailInput.value.trim() : null;

  try {
    const result = await Api.sendTestEmail(customEmail || undefined);
    if (statusBox) {
      if (!result.success) {
        statusBox.className = 'detection-status-hud suspicious';
        statusBox.innerHTML = `<strong>TEST EMAIL FAILED:</strong> ${result.error || 'Unknown error'}`;
      } else {
        statusBox.className = 'detection-status-hud normal';
        statusBox.innerHTML = `<strong>SUCCESS:</strong> Test email sent via ${result.provider.toUpperCase()} to ${result.recipient}!`;
      }
    }
    refreshEmailDashboard();
  } catch (err) {
    if (statusBox) {
      statusBox.className = 'detection-status-hud suspicious';
      statusBox.innerHTML = `<strong>Test email request failed:</strong> ${err.message}`;
    }
  }
}

async function handleSendAlertEmail() {
  const statusBox = document.getElementById('emailTestStatus');
  if (statusBox) {
    statusBox.style.display = 'block';
    statusBox.className = 'detection-status-hud analyzing';
    statusBox.textContent = 'Formatting and dispatching Suspicious Activity Alert Email to all Admin recipients...';
  }

  try {
    const result = await Api.sendAlertEmail({
      activity_type: 'Suspicious Loitering / Intrusion',
      camera_id: 'CAM-01',
      location: 'Main Security Entrance',
      risk_priority: 'HIGH'
    });

    if (statusBox) {
      if (!result.success) {
        statusBox.className = 'detection-status-hud suspicious';
        statusBox.innerHTML = `<strong>ALERT EMAIL FAILED:</strong> ${result.error || 'No active recipients configured'}`;
      } else {
        statusBox.className = 'detection-status-hud normal';
        statusBox.innerHTML = `<strong>ALERT EMAIL DISPATCHED:</strong> ${result.message}`;
      }
    }
    refreshEmailDashboard();
  } catch (err) {
    if (statusBox) {
      statusBox.className = 'detection-status-hud suspicious';
      statusBox.innerHTML = `<strong>Alert email dispatch failed:</strong> ${err.message}`;
    }
  }
}

async function handleRetryEmail(emailLogId) {
  if (!confirm(`Retry email dispatch for log #${emailLogId}?`)) return;
  try {
    const res = await Api.retryEmail(emailLogId);
    alert(res.message || (res.success ? 'Email retry dispatched!' : 'Email retry failed: ' + res.error));
    refreshEmailDashboard();
  } catch (err) {
    alert(`Retry failed: ${err.message}`);
  }
}

async function refreshEmailDashboard() {
  await loadEmailProviderStatus();
  await loadRecipientsList();
  await loadEmailLogsTable();
}

// =====================================================
// NOTIFICATION RECIPIENTS MANAGEMENT
// =====================================================

function toggleAddRecipientForm() {
  const form = document.getElementById('addRecipientForm');
  if (form) {
    form.style.display = form.style.display === 'none' ? 'block' : 'none';
    if (form.style.display === 'block') {
      const nameInput = document.getElementById('recipientNameInput');
      if (nameInput) nameInput.focus();
    }
    const errBox = document.getElementById('addRecipientError');
    if (errBox) errBox.style.display = 'none';
  }
}

async function handleAddRecipient() {
  const nameInput = document.getElementById('recipientNameInput');
  const emailInput = document.getElementById('recipientEmailInput');
  const typeInput = document.getElementById('recipientTypeInput');
  const errBox = document.getElementById('addRecipientError');

  const recipientType = typeInput ? typeInput.value : 'friend';
  const name = (nameInput ? nameInput.value.trim() : '') || (recipientType === 'admin' ? 'Admin Recipient' : 'Friend Recipient');
  const email = emailInput ? emailInput.value.trim() : '';

  if (!email) {
    if (errBox) { errBox.textContent = 'Email address is required.'; errBox.style.display = 'block'; }
    return;
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    if (errBox) { errBox.textContent = `"${email}" is not a valid email address.`; errBox.style.display = 'block'; }
    return;
  }

  try {
    await Api.addEmailRecipient(name, email, recipientType);
    if (nameInput) nameInput.value = '';
    if (emailInput) emailInput.value = '';
    if (typeInput) typeInput.value = 'friend';
    if (errBox) errBox.style.display = 'none';
    toggleAddRecipientForm();
    await loadRecipientsList();
    await loadEmailProviderStatus();
  } catch (err) {
    if (errBox) { errBox.textContent = err.message; errBox.style.display = 'block'; }
  }
}

async function handleDeleteRecipient(recipientId) {
  if (!confirm(`Permanently delete recipient #${recipientId}? This cannot be undone.`)) return;
  try {
    await Api.deleteEmailRecipient(recipientId);
    await loadRecipientsList();
    await loadEmailProviderStatus();
  } catch (err) {
    alert(`Failed to delete: ${err.message}`);
  }
}

async function handleToggleRecipient(recipientId, currentState) {
  try {
    await Api.updateEmailRecipient(recipientId, { is_active: !currentState });
    await loadRecipientsList();
    await loadEmailProviderStatus();
  } catch (err) {
    alert(`Failed to update: ${err.message}`);
  }
}

async function loadRecipientsList() {
  const container = document.getElementById('recipientsListContainer');
  if (!container) return;

  try {
    const data = await Api.getEmailRecipients();
    const recipients = Array.isArray(data) ? data : (data.recipients || []);

    if (recipients.length === 0) {
      container.innerHTML = `
        <div style="grid-column:1/-1; text-align:center; padding:24px; color:var(--text-dim); font-size:13px;">
          <i class="fas fa-user-slash" style="font-size:24px; margin-bottom:8px; display:block; opacity:0.4;"></i>
          No recipients configured yet.<br>
          <span style="font-size:11px; color:var(--text-muted);">Add an admin or friend email address above, or set <code>ADMIN_EMAIL</code> in your <code>.env</code> file.</span>
        </div>`;
      return;
    }

    container.innerHTML = recipients.map(r => {
      const isDb = r.source === 'database';
      const isEnv = r.source === 'environment';
      const isUser = r.source === 'user';
      const sourceColor = isDb ? 'var(--primary-blue)' : (isEnv ? 'var(--warning-amber)' : 'var(--success-green)');
      const sourceIcon = isDb ? 'fa-database' : (isEnv ? 'fa-file-code' : 'fa-user-shield');
      const sourceLabel = isDb ? 'Database' : (isEnv ? 'Env Variable' : 'Admin User');
      const activeColor = r.is_active ? 'var(--success-green)' : 'var(--text-dim)';
      const activeIcon = r.is_active ? 'fa-circle-check' : 'fa-circle-xmark';
      const activeText = r.is_active ? 'Active' : 'Inactive';

      // Recipient type badge
      const recType = (r.recipient_type || 'admin').toLowerCase();
      const typeColor = recType === 'admin' ? '#f59e0b' : '#8b5cf6';
      const typeIcon = recType === 'admin' ? 'fa-user-shield' : 'fa-user-group';
      const typeLabel = recType === 'admin' ? 'Admin' : 'Friend';

      const actions = isDb ? `
        <div style="display:flex; gap:4px; margin-top:8px;">
          <button class="btn btn-secondary" style="font-size:10px; padding:3px 8px;" onclick="handleToggleRecipient(${r.id}, ${r.is_active})" title="${r.is_active ? 'Pause alerts' : 'Resume alerts'}">
            <i class="fas ${r.is_active ? 'fa-pause' : 'fa-play'}"></i> ${r.is_active ? 'Pause' : 'Resume'}
          </button>
          <button class="btn btn-secondary" style="font-size:10px; padding:3px 8px; color:var(--danger-red); border-color:rgba(239,68,68,0.3);" onclick="handleDeleteRecipient(${r.id})" title="Delete recipient">
            <i class="fas fa-trash-can"></i> Remove
          </button>
        </div>` : `
        <div style="margin-top:8px; font-size:10px; color:var(--text-dim); font-style:italic;">
          <i class="fas fa-lock" style="margin-right:3px;"></i>Managed via ${sourceLabel.toLowerCase()} — edit in ${isEnv ? '.env file' : 'user settings'}
        </div>`;

      return `
        <div style="background:var(--bg-light, #0f172a); border:1px solid ${r.is_active ? 'var(--border-light, #334155)' : 'rgba(100,116,139,0.2)'}; border-radius:var(--radius-sm); padding:12px; transition:border-color 0.2s; ${!r.is_active ? 'opacity:0.6;' : ''}">
          <div style="display:flex; justify-content:space-between; align-items:flex-start;">
            <div>
              <div style="font-size:13px; font-weight:600; color:var(--text-primary); margin-bottom:2px;">
                <i class="fas fa-envelope" style="color:var(--primary-blue); margin-right:5px; font-size:11px;"></i>
                ${r.name || (recType === 'admin' ? 'Admin Recipient' : 'Friend Recipient')}
              </div>
              <div style="font-family:var(--font-mono); font-size:14px; font-weight:700; color:var(--primary-blue); letter-spacing:0.5px;">
                ${r.email_masked || '***'}
              </div>
            </div>
            <div style="display:flex; flex-direction:column; align-items:flex-end; gap:4px;">
              <span style="font-size:10px; padding:2px 6px; border-radius:4px; background:${typeColor}22; border:1px solid ${typeColor}44; color:${typeColor}; font-weight:700;">
                <i class="fas ${typeIcon}" style="margin-right:2px;"></i>${typeLabel}
              </span>
              <span style="font-size:10px; padding:2px 6px; border-radius:4px; background:rgba(99,102,241,0.1); border:1px solid rgba(99,102,241,0.2); color:${sourceColor}; font-weight:600;">
                <i class="fas ${sourceIcon}" style="margin-right:2px;"></i>${sourceLabel}
              </span>
              <span style="font-size:10px; color:${activeColor}; font-weight:600;">
                <i class="fas ${activeIcon}" style="margin-right:2px;"></i>${activeText}
              </span>
            </div>
          </div>
          ${actions}
        </div>`;
    }).join('');

  } catch (err) {
    container.innerHTML = `<div style="grid-column:1/-1; text-align:center; padding:16px; color:var(--danger-red); font-size:12px;"><i class="fas fa-triangle-exclamation"></i> Failed to load recipients: ${err.message}</div>`;
  }
}

async function loadEmailLogsTable() {
  const tbody = document.getElementById('emailLogsTableBody');
  if (!tbody) return;

  const filterSelect = document.getElementById('emailLogFilter');
  const filterVal = filterSelect ? filterSelect.value : 'all';

  try {
    const params = {};
    if (filterVal === 'failed') params.status = 'FAILED';
    if (filterVal === 'sent') params.status = 'SENT';
    const logs = await Api.getEmailLogs(params);

    const countEl = document.getElementById('emailLogCount');
    if (countEl) countEl.textContent = `Showing ${logs.length} logs`;

    if (logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:20px; color:var(--text-dim);">No email alerts match the selected criteria.</td></tr>';
      return;
    }

    tbody.innerHTML = logs.map(l => {
      const statusUpper = (l.status || '').toUpperCase();
      let statusClass = 'badge-normal';
      if (statusUpper === 'ACCEPTED' || statusUpper === 'SENT') {
        statusClass = 'badge-success';
      } else if (statusUpper === 'DELIVERED') {
        statusClass = 'badge-success';
      } else if (statusUpper === 'FAILED' || statusUpper === 'BOUNCED') {
        statusClass = 'badge-danger';
      } else if (statusUpper === 'SENDING' || statusUpper === 'QUEUED') {
        statusClass = 'badge-priority-medium';
      }

      const isEligibleForRetry = statusUpper === 'FAILED' || statusUpper === 'BOUNCED';
      const retryBtn = isEligibleForRetry
        ? `<button class="btn btn-secondary" style="padding:2px 8px; font-size:11px;" onclick="handleRetryEmail(${l.id})"><i class="fas fa-rotate-right"></i> Retry</button>`
        : '--';

      const incidentLink = l.incident_id
        ? `<a href="javascript:void(0)" onclick="openEventReviewModal('${l.incident_id}')" style="font-family:var(--font-mono); color:var(--primary-blue); font-weight:600;">${l.incident_id}</a>`
        : (l.is_test ? '<span style="color:var(--text-dim); font-size:11px;">[TEST EMAIL]</span>' : '--');

      const isError = isEligibleForRetry && l.error_message;
      const errorTooltip = isError ? ` title="${(l.error_message || '').replace(/"/g, '&quot;')}"` : '';
      const errorSubtext = isError
        ? `<div style="font-size:10px; color:var(--danger-red); margin-top:2px; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${(l.error_message || '').replace(/"/g, '&quot;')}">${l.error_message}</div>`
        : '';

      return `
        <tr>
          <td>#${l.id}</td>
          <td>${incidentLink}</td>
          <td style="font-family:var(--font-mono); font-size:11px;">${l.recipient_email_masked || '--'}</td>
          <td><span class="badge badge-normal">${(l.provider || 'APPS_SCRIPT').toUpperCase()}</span></td>
          <td style="font-size:11px; max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${(l.subject || '').replace(/"/g, '&quot;')}">${l.subject || '--'}</td>
          <td${errorTooltip}>
            <span class="badge ${statusClass}">${l.status || 'UNKNOWN'}</span>
            ${errorSubtext}
          </td>
          <td style="font-size:11px;">${l.sent_at ? new Date(l.sent_at).toLocaleString() : (l.created_at ? new Date(l.created_at).toLocaleString() : '--')}</td>
          <td>${retryBtn}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" style="color:var(--danger-red);">Failed to load email logs: ${err.message}</td></tr>`;
  }
}

async function loadAuditLogsTable() {
  const tbody = document.getElementById('auditLogsTableBody');
  if (!tbody) return;

  try {
    const logs = await Api.getAuditLogs();
    if (logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:20px; color:var(--text-dim);">No security audit records logged yet.</td></tr>';
      return;
    }

    tbody.innerHTML = logs.map(l => `
      <tr>
        <td>#${l.id}</td>
        <td style="font-size:11px;">${new Date(l.timestamp).toLocaleString()}</td>
        <td><strong>${l.actor_name || 'System'}</strong></td>
        <td><span class="badge badge-priority-medium">${l.action}</span></td>
        <td>${l.entity_type || '--'}: ${l.entity_id || '--'}</td>
        <td style="font-family:var(--font-mono); font-size:11px;">${l.ip_address || '--'}</td>
        <td style="font-size:12px;">${l.details || '--'}</td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="color:var(--danger-red);">Failed to load audit logs: ${err.message}</td></tr>`;
  }
}

// =====================================================
// CAMERAS MANAGEMENT
// =====================================================
async function loadCamerasList() {
  const container = document.getElementById('camerasListContainer');
  const selects = [
    document.getElementById('videoCameraSelect'),
    document.getElementById('filterCamera'),
    document.getElementById('liveCameraSelect')
  ];

  try {
    const cameras = await Api.getCameras();
    camerasList = cameras;

    // Update Dropdowns
    selects.forEach(sel => {
      if (!sel) return;
      const currentVal = sel.value;
      sel.innerHTML = (sel.id === 'filterCamera') ? '<option value="">All Cameras</option>' : '';
      cameras.forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.camera_id;
        opt.textContent = `${c.camera_id} • ${c.name} (${c.location})`;
        sel.appendChild(opt);
      });
      if (currentVal) sel.value = currentVal;
    });

    if (!container) return;

    container.innerHTML = cameras.map(c => `
      <div class="camera-card" style="background:#fff; border:1px solid var(--border-light); border-radius:var(--radius-md); padding:16px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <span style="font-family:var(--font-mono); font-weight:700; color:var(--primary-blue); font-size:13px;">${c.camera_id}</span>
          <span class="badge badge-normal">${c.status || 'ACTIVE'}</span>
        </div>
        <h4 style="font-size:15px; font-weight:700; color:var(--text-primary); margin-bottom:4px;">${c.name}</h4>
        <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">
          <i class="fas fa-location-dot"></i> ${c.location}
        </div>
        <p style="font-size:12px; color:var(--text-dim); line-height:1.4; margin-bottom:12px;">${c.description || 'Surveillance Feed'}</p>
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <small style="font-family:var(--font-mono); font-size:10px; color:var(--text-dim);">Zone: ${c.restricted_zone_coords ? 'Configured' : 'None'}</small>
          <button class="btn btn-secondary" style="padding:4px 8px; font-size:11px;" onclick="handleDeleteCamera('${c.camera_id}')">
            <i class="fas fa-trash" style="color:var(--danger-red);"></i>
          </button>
        </div>
      </div>
    `).join('');

  } catch (err) {
    console.error('Failed to load cameras:', err);
  }
}

async function handleDeleteCamera(cameraId) {
  if (confirm(`Are you sure you want to delete camera ${cameraId}?`)) {
    try {
      await Api.deleteCamera(cameraId);
      await loadCamerasList();
      loadDashboardData();
    } catch (e) {
      alert(`Delete failed: ${e.message}`);
    }
  }
}

// =====================================================
// FORM HANDLERS & LISTENERS
// =====================================================
function initForms() {
  // Login Form
  const loginForm = document.getElementById('authLoginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const u = document.getElementById('loginUsernameInput').value.trim();
      const p = document.getElementById('loginPasswordInput').value;
      try {
        const resp = await Api.login(u, p);
        updateUserUi(resp.user);
        hideAuthModal();
        loadInitialData();
      } catch (err) {
        showAuthModal(err.message || 'Invalid username or password');
      }
    });
  }

  // File Dropzone & External Video Ingestion
  const dropzone = document.getElementById('fileDropzone');
  const fileInput = document.getElementById('videoFileInput');
  if (fileInput) {
    fileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) handleSelectedVideoFile(file);
    });
  }

  const startProcessBtn = document.getElementById('startProcessBtn');
  if (startProcessBtn) {
    startProcessBtn.addEventListener('click', async () => {
      const file = fileInput ? fileInput.files[0] : null;
      if (!file) {
        alert('Please select a video file first.');
        return;
      }
      const camSelect = document.getElementById('videoCameraSelect');
      const cameraId = camSelect ? camSelect.value : 'CAM-01';
      const timestamp = document.getElementById('customTimestampInput').value;

      const fd = new FormData();
      fd.append('video_file', file);
      fd.append('camera_id', cameraId);
      if (timestamp) fd.append('custom_timestamp', timestamp);

      await executeVideoProcessing(fd);
    });
  }

  // Filter Listeners
  ['searchInput', 'filterCamera', 'filterStatus', 'filterPriority'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', () => loadEventsTable());
  });

  // Review Form Submission
  const reviewForm = document.getElementById('reviewModalForm');
  if (reviewForm) {
    reviewForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const eventId = document.getElementById('modalEventId').textContent;
      const status = document.getElementById('reviewDecisionSelect').value;
      const notes = document.getElementById('reviewNotesInput').value;
      const reviewer = document.getElementById('reviewerNameInput').value;

      try {
        await Api.submitReview({
          event_id: eventId,
          review_status: status,
          annotation: notes,
          reviewed_by: reviewer
        });
        closeReviewModal();
        loadEventsTable();
        loadAlertsQueue();
        loadDashboardData();
        alert('Security review recorded successfully.');
      } catch (err) {
        alert(`Review submission failed: ${err.message}`);
      }
    });
  }

  // Add Camera Form
  const createCamForm = document.getElementById('createCameraForm');
  if (createCamForm) {
    createCamForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const data = {
        camera_id: document.getElementById('camIdInput').value.trim(),
        name: document.getElementById('camNameInput').value.trim(),
        stream_url: document.getElementById('camStreamUrlInput').value.trim(),
        location: document.getElementById('camLocationInput').value.trim(),
        description: document.getElementById('camDescInput').value.trim(),
        restricted_zone_coords: document.getElementById('camCoordsInput').value.trim()
      };
      try {
        await Api.createCamera(data);
        document.getElementById('cameraModalBackdrop').style.display = 'none';
        createCamForm.reset();
        await loadCamerasList();
        loadDashboardData();
      } catch (err) {
        alert(`Failed to create camera: ${err.message}`);
      }
    });
  }

  // Retrain Model Button
  const retrainBtn = document.getElementById('retrainModelBtn');
  if (retrainBtn) {
    retrainBtn.addEventListener('click', async () => {
      const algo = document.getElementById('mlAlgoSelect').value;
      const msg = document.getElementById('retrainStatusMsg');
      if (msg) {
        msg.style.display = 'block';
        msg.style.color = 'var(--primary-blue)';
        msg.textContent = 'Retraining baseline anomaly detector...';
      }
      try {
        const resp = await Api.retrainModel(algo);
        if (msg) {
          msg.style.color = 'var(--success-green)';
          msg.textContent = `Model successfully retrained using ${resp.algorithm}! (Baseline: ${resp.baseline_samples} events)`;
        }
      } catch (err) {
        if (msg) {
          msg.style.color = 'var(--danger-red)';
          msg.textContent = `Retraining failed: ${err.message}`;
        }
      }
    });
  }
}

function handleSelectedVideoFile(file) {
  const info = document.getElementById('videoFileSelectedInfo');
  const nameEl = document.getElementById('selectedFileName');
  const sizeEl = document.getElementById('selectedFileSize');
  const preview = document.getElementById('externalVideoPreview');
  const placeholder = document.getElementById('videoPreviewPlaceholder');

  if (info && nameEl && sizeEl) {
    nameEl.textContent = file.name;
    sizeEl.textContent = `${(file.size / (1024 * 1024)).toFixed(2)} MB`;
    info.style.display = 'block';
  }

  if (preview && placeholder) {
    preview.src = URL.createObjectURL(file);
    preview.style.display = 'block';
    placeholder.style.display = 'none';
  }
}

// =====================================================
// MOBILE SECURITY CAMERA — Complete Production Implementation
// =====================================================
// Root-cause fixes applied:
//  1. Correct API endpoints: /api/v1/live/detect and /api/v1/live/evidence/save
//  2. Single state machine — one authoritative state drives all UI elements
//  3. Real backend inference via YOLOv8 (falls back gracefully if model missing)
//  4. Motion from backend MOG2 (not DIY pixel diff with wrong normalization)
//  5. HUD and metric cards updated from the same result object
//  6. STATUS card shows actual monitoring state, not camera-ready state
//  7. Recording + upload to correct endpoint with proper form fields
//  8. Clips-saved increments only after confirmed server 200 response
//  9. Backend warmup notification (MOG2 learns first ~5s, motion may be high)
// 10. Deduplication cooldown prevents re-triggering clips for same incident

// ── State Enum ──────────────────────────────────────────────────────────────
const MobileCamState = Object.freeze({
  CAMERA_OFF:      'CAMERA_OFF',
  CAMERA_READY:    'CAMERA_READY',
  MONITORING:      'MONITORING',
  RECORDING:       'RECORDING',
  SAVING_EVIDENCE: 'SAVING_EVIDENCE',
  ERROR:           'ERROR',
});

// ── Module Variables ─────────────────────────────────────────────────────────
let _mcState          = MobileCamState.CAMERA_OFF;
let _mcStream         = null;
let _mcSessionId      = null;       // backend DetectionSession ID
let _mcMonInterval    = null;       // setInterval handle
let _mcMediaRecorder  = null;
let _mcChunks         = [];
let _mcIsRecording    = false;
let _mcClipsSaved     = 0;
let _mcLastEventId    = null;       // last event_id from backend (for evidence link)
let _mcIncidentCooldownUntil = 0;   // Unix ms — no new clip until this time
let _mcWarmupFrames   = 0;          // count frames sent; first 5 flagged as warmup
let _mcFrameCounter   = 0;          // total frames processed this session

const MC_COOLDOWN_MS    = 30_000;   // 30 s between clips for same camera
const MC_WARMUP_FRAMES  = 5;        // backend MOG2 warmup period
const MC_DETECT_API     = '/api/v1/live/detect';
const MC_EVIDENCE_API   = '/api/v1/live/evidence/save';
const MC_SESSION_START  = '/api/v1/live/session/start';
const MC_SESSION_STOP   = '/api/v1/live/session/stop';

function mcSetState(newState, opts = {}) {
  _mcState = newState;
  _mcApplyStateToUI(newState, opts);
}

function _mcApplyStateToUI(state, opts) {
  // ── HUD banner ──
  const hudEl      = document.getElementById('mobileCameraStatusHud');
  const titleEl    = document.getElementById('mobileStatusTitle');
  const detailEl   = document.getElementById('mobileStatusDetails');

  const hudCls = {
    [MobileCamState.CAMERA_OFF]:      'standby',
    [MobileCamState.CAMERA_READY]:    'active',
    [MobileCamState.MONITORING]:      'active',
    [MobileCamState.RECORDING]:       'alert',
    [MobileCamState.SAVING_EVIDENCE]: 'alert',
    [MobileCamState.ERROR]:           'standby',
  };
  if (hudEl) hudEl.className = 'detection-status-hud ' + (hudCls[state] || 'standby');
  if (titleEl)  titleEl.textContent  = opts.title  || _mcDefaultTitle(state);
  if (detailEl) detailEl.textContent = opts.detail || _mcDefaultDetail(state);

  // ── Status metric card ──
  const statusLabels = {
    [MobileCamState.CAMERA_OFF]:      'OFF',
    [MobileCamState.CAMERA_READY]:    'READY',
    [MobileCamState.MONITORING]:      'LIVE',
    [MobileCamState.RECORDING]:       '● REC',
    [MobileCamState.SAVING_EVIDENCE]: 'SAVING',
    [MobileCamState.ERROR]:           'ERROR',
  };
  const statusColors = {
    [MobileCamState.CAMERA_OFF]:      'var(--text-muted)',
    [MobileCamState.CAMERA_READY]:    'var(--primary-blue)',
    [MobileCamState.MONITORING]:      'var(--success-green)',
    [MobileCamState.RECORDING]:       'var(--danger-red)',
    [MobileCamState.SAVING_EVIDENCE]: 'var(--warning-amber)',
    [MobileCamState.ERROR]:           'var(--danger-red)',
  };
  const el = document.getElementById('mobileMetricMonitoring');
  if (el) {
    el.textContent = statusLabels[state] || state;
    el.style.color = statusColors[state] || 'var(--text-muted)';
  }

  // ── Button visibility ──
  const show = (id, visible) => {
    const b = document.getElementById(id);
    if (b) b.style.display = visible ? 'inline-flex' : 'none';
  };
  const disabled = (id, yes) => {
    const b = document.getElementById(id);
    if (b) b.disabled = yes;
  };

  show('btnMobileStartCamera',    state === MobileCamState.CAMERA_OFF || state === MobileCamState.ERROR);
  show('btnMobileStopCamera',     state !== MobileCamState.CAMERA_OFF && state !== MobileCamState.ERROR);
  show('btnMobileStartMonitoring',state === MobileCamState.CAMERA_READY);
  show('btnMobileStopMonitoring', state === MobileCamState.MONITORING ||
                                  state === MobileCamState.RECORDING ||
                                  state === MobileCamState.SAVING_EVIDENCE);
  disabled('btnMobileStopCamera', state === MobileCamState.SAVING_EVIDENCE);

  // ── Viewfinder ──
  const video = document.getElementById('mobileCameraVideo');
  const placeholder = document.getElementById('mobileOffPlaceholder');
  const hud = document.getElementById('mobileHudOverlay');
  const isOn = state !== MobileCamState.CAMERA_OFF && state !== MobileCamState.ERROR;
  if (video)       video.style.display       = isOn ? 'block' : 'none';
  if (placeholder) placeholder.style.display = isOn ? 'none' : 'block';
  if (hud)         hud.style.display         = isOn ? 'flex' : 'none';

  // ── REC indicator ──
  const recInd = document.getElementById('mobileRecIndicator');
  if (recInd) recInd.style.display = (state === MobileCamState.RECORDING) ? 'flex' : 'none';
}

function _mcDefaultTitle(state) {
  return {
    [MobileCamState.CAMERA_OFF]:      'CAMERA OFF — Press Start Camera to begin',
    [MobileCamState.CAMERA_READY]:    'CAMERA ACTIVE — Press Start Monitoring to begin AI surveillance',
    [MobileCamState.MONITORING]:      'MONITORING — AI Surveillance Running',
    [MobileCamState.RECORDING]:       'RECORDING — Capturing Evidence Clip',
    [MobileCamState.SAVING_EVIDENCE]: 'SAVING — Uploading Evidence to Server',
    [MobileCamState.ERROR]:           'ERROR — Check camera permissions',
  }[state] || state;
}

function _mcDefaultDetail(state) {
  return {
    [MobileCamState.CAMERA_OFF]:      'Camera permission required',
    [MobileCamState.CAMERA_READY]:    'Session: None | Frame inference: Not started',
    [MobileCamState.MONITORING]:      `Session: ${_mcSessionId || 'N/A'} | CAM-MOBILE`,
    [MobileCamState.RECORDING]:       `Session: ${_mcSessionId || 'N/A'} | Recording evidence clip`,
    [MobileCamState.SAVING_EVIDENCE]: 'Uploading to server — do not close the page',
    [MobileCamState.ERROR]:           'Grant camera permission and refresh if needed',
  }[state] || '';
}

// ── Reset all metrics to zero ─────────────────────────────────────────────────
function _mcClearMetrics() {
  const set = (id, v, color) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = v;
    if (color !== undefined) el.style.color = color;
  };
  set('mobileMetricPersonCount', '0');
  set('mobileMetricMotion',      '0.0%');
  set('mobileMetricAnomalyScore','0.00');
  set('mobileMetricRisk',        'NORMAL', 'var(--success-green)');
  const hudStats = document.getElementById('mobileHudStats');
  if (hudStats) hudStats.textContent = 'PEOPLE: — | MOTION: — | SCORE: —';
}

// ── Update all metrics from a backend result ──────────────────────────────────
function _mcApplyResult(result) {
  const personCount   = result.person_count  ?? 0;
  const motionScore   = result.motion_score  ?? 0;
  const anomalyScore  = result.anomaly_score ?? 0;
  const riskPriority  = result.risk_priority || 'LOW';
  const motionPct     = (motionScore * 100).toFixed(1);

  // Risk colour mapping
  const riskMap = {
    HIGH:   { label: 'HIGH',   color: 'var(--danger-red)' },
    MEDIUM: { label: 'MEDIUM', color: 'var(--warning-amber)' },
    LOW:    { label: 'NORMAL', color: 'var(--success-green)' },
  };
  const { label: riskLabel, color: riskColor } = riskMap[riskPriority] || riskMap.LOW;

  // Metric cards
  const set = (id, v, color) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = v;
    if (color !== undefined) el.style.color = color;
  };
  set('mobileMetricPersonCount',  String(personCount));
  set('mobileMetricMotion',       motionPct + '%');
  set('mobileMetricAnomalyScore', anomalyScore.toFixed(2));
  set('mobileMetricRisk',         riskLabel, riskColor);

  // HUD overlay (single source of truth with metric cards)
  const hudStats = document.getElementById('mobileHudStats');
  if (hudStats) {
    hudStats.textContent = `PEOPLE: ${personCount} | MOTION: ${motionPct}% | SCORE: ${anomalyScore.toFixed(2)}`;
  }

  // Draw bounding boxes on canvas overlay
  _mcDrawBoxes(result.normalized_boxes || [], personCount);
}

// ── Bounding-box overlay on canvas ───────────────────────────────────────────
function _mcDrawBoxes(normalizedBoxes, personCount) {
  const video  = document.getElementById('mobileCameraVideo');
  const canvas = document.getElementById('mobileDetectionCanvas');
  if (!canvas || !video) return;

  // Sync canvas size with video element
  const vw = video.videoWidth  || video.clientWidth;
  const vh = video.videoHeight || video.clientHeight;
  canvas.width  = video.clientWidth;
  canvas.height = video.clientHeight;

  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  if (!normalizedBoxes || normalizedBoxes.length === 0) return;

  ctx.strokeStyle = '#22c55e';
  ctx.lineWidth   = 2;
  ctx.font        = 'bold 12px Inter, sans-serif';
  ctx.fillStyle   = 'rgba(34,197,94,0.85)';

  normalizedBoxes.forEach(([nx, ny, nw, nh], i) => {
    const px = nx * canvas.width;
    const py = ny * canvas.height;
    const pw = nw * canvas.width;
    const ph = nh * canvas.height;
    ctx.strokeRect(px, py, pw, ph);
    ctx.fillRect(px, py - 18, 62, 18);
    ctx.fillStyle = '#000';
    ctx.fillText(`Person ${i + 1}`, px + 4, py - 4);
    ctx.fillStyle = 'rgba(34,197,94,0.85)';
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC HANDLERS (called from HTML onclick)
// ─────────────────────────────────────────────────────────────────────────────

async function handleMobileStartCamera() {
  if (_mcState !== MobileCamState.CAMERA_OFF && _mcState !== MobileCamState.ERROR) return;

  const errBox = document.getElementById('mobileCameraPermError');
  if (errBox) errBox.style.display = 'none';

  const facingMode = document.getElementById('mobileFacingSelect')?.value || 'environment';
  mcSetState(MobileCamState.CAMERA_OFF, {
    title: 'Requesting camera permission...',
    detail: 'Please allow camera access in your browser prompt.'
  });

  try {
    _mcStream = await navigator.mediaDevices.getUserMedia({
      video: {
        facingMode,
        width:  { ideal: 640 },
        height: { ideal: 480 },
        frameRate: { ideal: 15, max: 30 }
      },
      audio: false
    });

    const video = document.getElementById('mobileCameraVideo');
    if (video) {
      video.srcObject = _mcStream;
      await video.play().catch(() => {});
    }

    _mcWarmupFrames  = 0;
    _mcFrameCounter  = 0;
    _mcClipsSaved    = 0;
    _mcLastEventId   = null;
    document.getElementById('mobileMetricClipsSaved').textContent = '0';
    _mcClearMetrics();
    mcSetState(MobileCamState.CAMERA_READY);

  } catch (err) {
    console.error('[MobileCam] Camera error:', err);
    mcSetState(MobileCamState.ERROR, {
      title: 'CAMERA ERROR — ' + (err.name || 'Unknown'),
      detail: err.message
    });
    const errBox = document.getElementById('mobileCameraPermError');
    const errTxt = document.getElementById('mobileCameraPermErrorText');
    if (errBox) errBox.style.display = 'block';
    if (errTxt) errTxt.textContent = err.name === 'NotAllowedError'
      ? 'Camera permission denied. Please allow access in your browser and try again.'
      : `Camera error: ${err.message}`;
  }
}

async function handleMobileStopCamera() {
  // Stop monitoring first (which cleans up MediaRecorder)
  if (_mcState === MobileCamState.MONITORING ||
      _mcState === MobileCamState.RECORDING  ||
      _mcState === MobileCamState.SAVING_EVIDENCE) {
    handleMobileStopMonitoring();
    // Give recorder a moment to finalize
    await new Promise(r => setTimeout(r, 400));
  }

  // Stop session on server if we have one
  if (_mcSessionId) {
    _mcStopSession(_mcSessionId).catch(() => {});
    _mcSessionId = null;
  }

  // Release camera tracks
  if (_mcStream) {
    _mcStream.getTracks().forEach(t => t.stop());
    _mcStream = null;
  }

  const video = document.getElementById('mobileCameraVideo');
  if (video) { video.srcObject = null; }

  const canvas = document.getElementById('mobileDetectionCanvas');
  if (canvas) {
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
  }

  _mcClearMetrics();
  mcSetState(MobileCamState.CAMERA_OFF);
}

async function handleMobileStartMonitoring() {
  if (_mcState !== MobileCamState.CAMERA_READY) return;
  if (!_mcStream) { alert('Camera is not active. Press Start Camera first.'); return; }

  // Start a detection session on the backend
  try {
    const durationSec = parseInt(document.getElementById('mobileRecordDuration')?.value || '15');
    const sessData = await _mcStartSession('CAM-MOBILE', durationSec);
    _mcSessionId = sessData?.session_id || null;
  } catch (err) {
    console.warn('[MobileCam] Could not start backend session:', err);
    // Continue anyway — session is optional
    _mcSessionId = null;
  }

  _mcFrameCounter = 0;
  _mcWarmupFrames = 0;
  _mcLastEventId  = null;
  _mcIncidentCooldownUntil = 0;

  mcSetState(MobileCamState.MONITORING);

  // Send a frame every 2.5 seconds for real inference
  _mcMonInterval = setInterval(_mcDetectionCycle, 2500);
}

function handleMobileStopMonitoring() {
  if (_mcState === MobileCamState.CAMERA_OFF ||
      _mcState === MobileCamState.CAMERA_READY ||
      _mcState === MobileCamState.ERROR) return;

  // Stop interval
  if (_mcMonInterval) {
    clearInterval(_mcMonInterval);
    _mcMonInterval = null;
  }

  // If recording, stop it and discard (partial clip not saved after deliberate stop)
  if (_mcIsRecording && _mcMediaRecorder && _mcMediaRecorder.state === 'recording') {
    _mcMediaRecorder.onstop = null; // Don't upload on deliberate stop
    _mcMediaRecorder.stop();
    _mcIsRecording = false;
  }
  _mcChunks = [];

  // Stop server session
  if (_mcSessionId) {
    _mcStopSession(_mcSessionId).catch(() => {});
    _mcSessionId = null;
  }

  mcSetState(MobileCamState.CAMERA_READY);
  _mcClearMetrics();
}

// ─────────────────────────────────────────────────────────────────────────────
// DETECTION CYCLE — called every 2.5 s by interval
// ─────────────────────────────────────────────────────────────────────────────
async function _mcDetectionCycle() {
  if (!_mcStream || _mcState === MobileCamState.CAMERA_OFF ||
      _mcState === MobileCamState.CAMERA_READY || _mcState === MobileCamState.ERROR) return;

  const video = document.getElementById('mobileCameraVideo');
  if (!video || video.readyState < 2) return; // Not ready

  // Capture frame to JPEG blob
  let frameBlob;
  try {
    frameBlob = await _mcCaptureFrame(video);
  } catch (e) {
    console.warn('[MobileCam] Frame capture failed:', e);
    return;
  }

  _mcFrameCounter++;
  _mcWarmupFrames++;
  const isWarmup = _mcWarmupFrames <= MC_WARMUP_FRAMES;

  // Send to backend for real inference
  let result;
  try {
    result = await _mcSendFrameToBackend(frameBlob);
  } catch (err) {
    console.warn('[MobileCam] Backend inference failed:', err);
    // Update HUD to show inference error, don't update metric cards with stale data
    const hudStats = document.getElementById('mobileHudStats');
    if (hudStats) hudStats.textContent = 'INFERENCE ERROR — Retrying...';
    return;
  }

  // If in warmup phase, show notice but still update metrics
  if (isWarmup) {
    const detail = `Session: ${_mcSessionId || 'N/A'} | Warmup frame ${_mcWarmupFrames}/${MC_WARMUP_FRAMES} (motion may be high)`;
    const hudEl = document.getElementById('mobileCameraStatusHud');
    if (hudEl) hudEl.title = detail;
  }

  // Update ALL metric displays from single result object
  _mcApplyResult(result);

  // Determine if a clip should be recorded
  const now = Date.now();
  const isSuspicious   = result.status === 'SUSPICIOUS';
  const isConfirmed    = result.is_confirmed === true;
  const pastCooldown   = now > _mcIncidentCooldownUntil;
  const notRecording   = !_mcIsRecording;
  const notSaving      = _mcState !== MobileCamState.SAVING_EVIDENCE;
  const notWarmup      = !isWarmup;

  if (isSuspicious && isConfirmed && pastCooldown && notRecording && notSaving && notWarmup) {
    _mcLastEventId = result.alert?.event_id || null;
    _mcIncidentCooldownUntil = now + MC_COOLDOWN_MS;

    // Show latest event box
    _mcShowLatestEvent(result);

    // Begin recording
    mcSetState(MobileCamState.RECORDING);
    _mcStartRecording();

  } else if (_mcState === MobileCamState.MONITORING && isSuspicious && !isConfirmed && !isWarmup) {
    // Show suspicious-but-not-yet-confirmed hint in HUD detail
    const detailEl = document.getElementById('mobileStatusDetails');
    if (detailEl) detailEl.textContent = `Suspicious activity building... ${result.activity_type || ''}`;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// FRAME CAPTURE
// ─────────────────────────────────────────────────────────────────────────────
function _mcCaptureFrame(videoEl) {
  return new Promise((resolve, reject) => {
    const canvas = document.createElement('canvas');
    canvas.width  = videoEl.videoWidth  || 640;
    canvas.height = videoEl.videoHeight || 480;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(videoEl, 0, 0, canvas.width, canvas.height);
    canvas.toBlob(blob => {
      if (!blob) reject(new Error('toBlob returned null'));
      else resolve(blob);
    }, 'image/jpeg', 0.82);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// BACKEND CALLS
// ─────────────────────────────────────────────────────────────────────────────
async function _mcSendFrameToBackend(frameBlob) {
  const token = Api.getToken();
  const form  = new FormData();
  form.append('frame',      frameBlob, 'mobile_frame.jpg');
  form.append('camera_id',  'CAM-MOBILE');
  form.append('location',   'Mobile Camera');
  if (_mcSessionId) form.append('session_id', _mcSessionId);

  const resp = await fetch(MC_DETECT_API, {
    method: 'POST',
    headers: token ? { 'Authorization': `Bearer ${token}` } : {},
    body: form,
  });

  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`Backend returned ${resp.status}: ${body.slice(0, 120)}`);
  }
  return await resp.json();
}

async function _mcStartSession(cameraId, durationSec) {
  const token = Api.getToken();
  const resp = await fetch(MC_SESSION_START, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      camera_id:   cameraId,
      device_info: navigator.userAgent,
    }),
  });
  if (!resp.ok) return null;
  return await resp.json();
}

async function _mcStopSession(sessionId) {
  const token = Api.getToken();
  const resp = await fetch(MC_SESSION_STOP, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ session_id: sessionId }),
  });
  return resp.ok ? await resp.json() : null;
}

async function _mcUploadEvidence(blob, durationSec) {
  const token = Api.getToken();
  const form  = new FormData();
  form.append('video_file',       blob, `mobile_evidence_${Date.now()}.webm`);
  form.append('duration_seconds', String(durationSec));
  if (_mcLastEventId)  form.append('event_id',   _mcLastEventId);
  if (_mcSessionId)    form.append('session_id', _mcSessionId);

  const resp = await fetch(MC_EVIDENCE_API, {
    method: 'POST',
    headers: token ? { 'Authorization': `Bearer ${token}` } : {},
    body: form,
  });

  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`Evidence upload failed ${resp.status}: ${body.slice(0, 120)}`);
  }
  return await resp.json();
}

// ─────────────────────────────────────────────────────────────────────────────
// RECORDING + UPLOAD
// ─────────────────────────────────────────────────────────────────────────────
function _mcStartRecording() {
  if (!_mcStream || _mcIsRecording) return;

  const durationSec = parseInt(document.getElementById('mobileRecordDuration')?.value || '15');

  // Pick best supported MIME type
  const mimeType = ['video/webm;codecs=vp9', 'video/webm;codecs=vp8', 'video/webm', 'video/mp4']
    .find(m => {
      try { return MediaRecorder.isTypeSupported(m); } catch { return false; }
    }) || 'video/webm';

  _mcChunks = [];
  _mcIsRecording = true;

  try {
    _mcMediaRecorder = new MediaRecorder(_mcStream, { mimeType, videoBitsPerSecond: 800_000 });
  } catch (err) {
    console.error('[MobileCam] MediaRecorder init failed:', err);
    _mcIsRecording = false;
    mcSetState(MobileCamState.MONITORING);
    return;
  }

  _mcMediaRecorder.ondataavailable = (e) => {
    if (e.data && e.data.size > 0) _mcChunks.push(e.data);
  };

  _mcMediaRecorder.onstop = async () => {
    if (!_mcChunks.length) {
      console.warn('[MobileCam] No chunks recorded — nothing to upload');
      _mcIsRecording = false;
      if (_mcState === MobileCamState.RECORDING) mcSetState(MobileCamState.MONITORING);
      return;
    }

    mcSetState(MobileCamState.SAVING_EVIDENCE);
    const blob = new Blob(_mcChunks, { type: mimeType });
    _mcChunks   = [];

    // Validate: must be at least 5 KB
    if (blob.size < 5120) {
      console.warn('[MobileCam] Clip too small to be valid:', blob.size);
      _mcIsRecording = false;
      mcSetState(MobileCamState.MONITORING);
      return;
    }

    try {
      const saved = await _mcUploadEvidence(blob, durationSec);
      _mcClipsSaved++;
      document.getElementById('mobileMetricClipsSaved').textContent = String(_mcClipsSaved);
      console.log('[MobileCam] Evidence saved:', saved.video_id);
    } catch (err) {
      console.error('[MobileCam] Evidence upload error:', err);
      // Show upload error in HUD without incrementing clips saved
      const detailEl = document.getElementById('mobileStatusDetails');
      if (detailEl) detailEl.textContent = 'Evidence upload failed: ' + err.message.slice(0, 80);
    }

    _mcIsRecording = false;
    // Return to monitoring state if still active
    if (_mcMonInterval) mcSetState(MobileCamState.MONITORING);
    else mcSetState(MobileCamState.CAMERA_READY);
  };

  _mcMediaRecorder.start(500); // collect chunks every 500ms

  // Countdown timer on REC indicator
  const recTimer = document.getElementById('mobileRecTimer');
  let remaining = durationSec;
  if (recTimer) recTimer.textContent = `0:${String(remaining).padStart(2, '0')}`;
  const countdown = setInterval(() => {
    remaining--;
    if (recTimer) recTimer.textContent = `0:${String(Math.max(0, remaining)).padStart(2, '0')}`;
    if (remaining <= 0) clearInterval(countdown);
  }, 1000);

  // Stop after clip duration
  setTimeout(() => {
    clearInterval(countdown);
    if (_mcMediaRecorder && _mcMediaRecorder.state === 'recording') {
      _mcMediaRecorder.stop();
    }
    _mcIsRecording = false;
  }, durationSec * 1000);
}

// ─────────────────────────────────────────────────────────────────────────────
// LATEST EVENT BOX
// ─────────────────────────────────────────────────────────────────────────────
function _mcShowLatestEvent(result) {
  const box = document.getElementById('mobileLatestEvent');
  const txt = document.getElementById('mobileLatestEventText');
  if (!box || !txt) return;

  const ts  = new Date().toLocaleTimeString();
  const evtId = result.alert?.event_id || 'Pending';
  const why   = result.anomaly_reasons || result.activity_type || 'Suspicious Activity';
  txt.textContent = `[${ts}] ${why} | Event: ${evtId} | Score: ${(result.anomaly_score || 0).toFixed(2)} | People: ${result.person_count || 0}`;
  box.style.display = 'block';
}
