/**
 * Enterprise REST API Client with JWT Authentication & Error Handling
 * SurveilGuard AI - Suspicious Activity Detection & Admin Monitoring System
 */

const API_BASE = '/api';

const Api = {
  // --- Token Management ---
  getToken() {
    return localStorage.getItem('surveilguard_jwt_token') || '';
  },

  setToken(token) {
    if (token) {
      localStorage.setItem('surveilguard_jwt_token', token);
    } else {
      localStorage.removeItem('surveilguard_jwt_token');
    }
  },

  getUser() {
    try {
      const u = localStorage.getItem('surveilguard_user');
      return u ? JSON.parse(u) : null;
    } catch {
      return null;
    }
  },

  setUser(user) {
    if (user) {
      localStorage.setItem('surveilguard_user', JSON.stringify(user));
    } else {
      localStorage.removeItem('surveilguard_user');
    }
  },

  getAuthHeaders(extraHeaders = {}) {
    const headers = { ...extraHeaders };
    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
  },

  async _fetch(url, options = {}) {
    options.headers = this.getAuthHeaders(options.headers || {});
    const res = await fetch(url, options);

    if (res.status === 401 && !url.includes('/auth/login')) {
      // Token expired or invalid
      this.setToken(null);
      this.setUser(null);
      window.dispatchEvent(new CustomEvent('auth:unauthorized'));
    }

    return res;
  },

  // --- Authentication ---
  async login(username, password) {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Login failed' }));
      throw new Error(err.detail || 'Login failed');
    }
    const data = await res.json();
    this.setToken(data.access_token);
    this.setUser(data.user);
    return data;
  },

  async getMe() {
    const res = await this._fetch(`${API_BASE}/auth/me`);
    if (!res.ok) throw new Error('Failed to retrieve current user profile');
    const user = await res.json();
    this.setUser(user);
    return user;
  },

  async logout() {
    try {
      await this._fetch(`${API_BASE}/auth/logout`, { method: 'POST' });
    } finally {
      this.setToken(null);
      this.setUser(null);
    }
  },

  // --- Cameras ---
  async getCameras() {
    const res = await this._fetch(`${API_BASE}/cameras`);
    if (!res.ok) throw new Error('Failed to fetch cameras');
    return res.json();
  },

  async createCamera(cameraData) {
    const res = await this._fetch(`${API_BASE}/cameras`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cameraData)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to create camera' }));
      throw new Error(err.detail || 'Failed to create camera');
    }
    return res.json();
  },

  async deleteCamera(cameraId) {
    const res = await this._fetch(`${API_BASE}/cameras/${cameraId}`, {
      method: 'DELETE'
    });
    if (!res.ok && res.status !== 204) throw new Error('Failed to delete camera');
    return true;
  },

  // --- Live Detection & Sessions ---
  async startDetectionSession(cameraId, deviceInfo = navigator.userAgent) {
    const res = await this._fetch(`${API_BASE}/v1/live/session/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ camera_id: cameraId, device_info: deviceInfo })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to start detection session' }));
      throw new Error(err.detail || 'Failed to start detection session');
    }
    return res.json();
  },

  async stopDetectionSession(sessionId) {
    const res = await this._fetch(`${API_BASE}/v1/live/session/stop`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to stop detection session' }));
      throw new Error(err.detail || 'Failed to stop detection session');
    }
    return res.json();
  },

  async getDetectionSessions(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await this._fetch(`${API_BASE}/v1/live/sessions?${query}`);
    if (!res.ok) throw new Error('Failed to fetch detection sessions');
    return res.json();
  },

  async detectLiveFrame(formData) {
    const res = await this._fetch(`${API_BASE}/v1/live/detect`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Live detection failed' }));
      throw new Error(err.detail || 'Live detection failed');
    }
    return res.json();
  },

  async saveEvidenceClip(formData) {
    const res = await this._fetch(`${API_BASE}/v1/live/evidence/save`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to save evidence video' }));
      throw new Error(err.detail || 'Failed to save evidence video');
    }
    return res.json();
  },

  async getLiveSettings() {
    const res = await this._fetch(`${API_BASE}/v1/live/settings`);
    if (!res.ok) throw new Error('Failed to fetch detection settings');
    return res.json();
  },

  async updateLiveSettings(settings) {
    const res = await this._fetch(`${API_BASE}/v1/live/settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    if (!res.ok) throw new Error('Failed to update detection settings');
    return res.json();
  },

  // --- Video Processing & Evidence ---
  async processVideo(formData) {
    const res = await this._fetch(`${API_BASE}/videos/upload-and-process`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Video processing failed' }));
      throw new Error(err.detail || 'Video processing failed');
    }
    return res.json();
  },

  async getSecureVideoUrl(videoId) {
    const res = await this._fetch(`${API_BASE}/videos/${videoId}/secure-url`);
    if (!res.ok) throw new Error('Failed to obtain secure video URL');
    return res.json();
  },

  // --- Events & Alerts ---
  async getEvents(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await this._fetch(`${API_BASE}/events?${query}`);
    if (!res.ok) throw new Error('Failed to fetch events');
    return res.json();
  },

  async getEventById(eventId) {
    const res = await this._fetch(`${API_BASE}/events/${eventId}`);
    if (!res.ok) throw new Error(`Failed to fetch event ${eventId}`);
    return res.json();
  },

  async getAlerts() {
    const res = await this._fetch(`${API_BASE}/alerts`);
    if (!res.ok) throw new Error('Failed to fetch alerts');
    return res.json();
  },

  // --- Human Review ---
  async submitReview(reviewData) {
    const res = await this._fetch(`${API_BASE}/reviews`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reviewData)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to submit review' }));
      throw new Error(err.detail || 'Failed to submit review');
    }
    return res.json();
  },

  // --- Analytics ---
  async getDashboardSummary() {
    const res = await this._fetch(`${API_BASE}/analytics/summary`);
    if (!res.ok) throw new Error('Failed to fetch dashboard summary');
    return res.json();
  },

  async getDashboardCharts() {
    const res = await this._fetch(`${API_BASE}/analytics/charts`);
    if (!res.ok) throw new Error('Failed to fetch dashboard charts');
    return res.json();
  },

  // --- Email Alerts & Notifications ---
  async getEmailStatus() {
    const res = await this._fetch(`${API_BASE}/email/status`);
    if (!res.ok) throw new Error('Failed to fetch email status');
    return res.json();
  },

  async sendTestEmail(toEmail) {
    const res = await this._fetch(`${API_BASE}/email/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: toEmail })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to dispatch test email' }));
      throw new Error(err.detail || 'Failed to dispatch test email');
    }
    return res.json();
  },

  async sendAlertEmail(params = {}) {
    const res = await this._fetch(`${API_BASE}/email/alert`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to dispatch alert email' }));
      throw new Error(err.detail || 'Failed to dispatch alert email');
    }
    return res.json();
  },

  async retryEmail(emailLogId) {
    const res = await this._fetch(`${API_BASE}/email/${emailLogId}/retry`, {
      method: 'POST'
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to retry email' }));
      throw new Error(err.detail || 'Failed to retry email');
    }
    return res.json();
  },

  async getEmailLogs(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await this._fetch(`${API_BASE}/email/logs?${query}`);
    if (!res.ok) throw new Error('Failed to fetch email logs');
    return res.json();
  },

  async sendIncidentEmail(incidentId) {
    const res = await this._fetch(`${API_BASE}/email/incident/${incidentId}/send`, {
      method: 'POST'
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to send incident email' }));
      throw new Error(err.detail || 'Failed to send incident email');
    }
    return res.json();
  },

  // --- Email Recipients Management ---
  async getEmailRecipients() {
    const res = await this._fetch(`${API_BASE}/email/recipients`);
    if (!res.ok) throw new Error('Failed to fetch email recipients');
    return res.json();
  },

  async addEmailRecipient(name, email, recipient_type = 'friend') {
    const res = await this._fetch(`${API_BASE}/email/recipients`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, recipient_type })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to add email recipient' }));
      throw new Error(err.detail || 'Failed to add email recipient');
    }
    return res.json();
  },

  async updateEmailRecipient(recipientId, data) {
    const res = await this._fetch(`${API_BASE}/email/recipients/${recipientId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to update email recipient' }));
      throw new Error(err.detail || 'Failed to update email recipient');
    }
    return res.json();
  },

  async deleteEmailRecipient(recipientId) {
    const res = await this._fetch(`${API_BASE}/email/recipients/${recipientId}`, {
      method: 'DELETE'
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to delete email recipient' }));
      throw new Error(err.detail || 'Failed to delete email recipient');
    }
    return res.json();
  },

  // --- Reports & Compliance ---
  async getActivityReport(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await this._fetch(`${API_BASE}/reports/activity?${query}`);
    if (!res.ok) throw new Error('Failed to generate activity report');
    return res.json();
  },

  getReportCSVDownloadUrl(period = 'daily', startDate = '', endDate = '', cameraId = '') {
    const params = new URLSearchParams({ period });
    if (startDate) params.append('start_date', startDate);
    if (endDate) params.append('end_date', endDate);
    if (cameraId) params.append('camera_id', cameraId);
    const token = this.getToken();
    if (token) params.append('token', token);
    return `${API_BASE}/reports/activity/csv?${params.toString()}`;
  },

  // --- Audit Logs ---
  async getAuditLogs(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await this._fetch(`${API_BASE}/audit/logs?${query}`);
    if (!res.ok) throw new Error('Failed to fetch audit logs');
    return res.json();
  },

  // --- ML Hub ---
  async retrainModel(algorithm, contamination = 0.08) {
    const res = await this._fetch(`${API_BASE}/ml/retrain?algorithm=${algorithm}&contamination=${contamination}`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error('Model retraining failed');
    return res.json();
  },

  // --- Admin Incidents & Push Devices ---
  async registerDevice(deviceData) {
    const res = await this._fetch(`${API_BASE}/admin/devices/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(deviceData)
    });
    if (!res.ok) throw new Error((await res.json()).detail || 'Failed to register device');
    return res.json();
  },

  async getDevices(activeOnly = true) {
    const res = await this._fetch(`${API_BASE}/admin/devices?active_only=${activeOnly}`);
    if (!res.ok) throw new Error('Failed to fetch devices');
    return res.json();
  },

  async unregisterDevice(deviceId) {
    const res = await this._fetch(`${API_BASE}/admin/devices/${deviceId}`, {
      method: 'DELETE'
    });
    if (!res.ok && res.status !== 204) throw new Error('Failed to unregister device');
    return true;
  },

  async getIncidents(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await this._fetch(`${API_BASE}/admin/incidents?${query}`);
    if (!res.ok) throw new Error('Failed to fetch incidents');
    return res.json();
  },

  async getIncidentById(incidentId) {
    const res = await this._fetch(`${API_BASE}/admin/incidents/${incidentId}`);
    if (!res.ok) throw new Error(`Failed to fetch incident ${incidentId}`);
    return res.json();
  },

  async acknowledgeIncident(incidentId) {
    const res = await this._fetch(`${API_BASE}/admin/incidents/${incidentId}/acknowledge`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error((await res.json()).detail || 'Failed to acknowledge incident');
    return res.json();
  },

  async resolveIncident(incidentId) {
    const res = await this._fetch(`${API_BASE}/admin/incidents/${incidentId}/resolve`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error((await res.json()).detail || 'Failed to resolve incident');
    return res.json();
  },

  async sendTestNotification(userId = 1) {
    const res = await this._fetch(`${API_BASE}/admin/notifications/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: userId })
    });
    if (!res.ok) throw new Error((await res.json()).detail || 'Failed to send test notification');
    return res.json();
  }
};
