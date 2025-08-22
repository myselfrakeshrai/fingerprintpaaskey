export async function getDeviceFingerprintHash() {
  try {
    if (window && window.FingerprintSDK && typeof window.FingerprintSDK.getHash === 'function') {
      const value = await window.FingerprintSDK.getHash();
      return typeof value === 'string' ? value : '';
    }
    if (window && typeof window.getFingerprintHash === 'function') {
      const value = await window.getFingerprintHash();
      return typeof value === 'string' ? value : '';
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn('[Fingerprint] capture failed:', e?.message || e);
  }
  // Demo fallback: derive a stable, pseudo device hash (no biometrics!) and cache it
  try {
    const cached = localStorage.getItem('demoDeviceFingerprintHash');
    if (cached) return cached;
    const parts = [
      navigator.userAgent || '',
      navigator.platform || '',
      navigator.language || '',
      String((typeof window !== 'undefined' && window.screen && window.screen.width) ? window.screen.width : ''),
      String((typeof window !== 'undefined' && window.screen && window.screen.height) ? window.screen.height : ''),
      String(new Date().getTimezoneOffset()),
    ].join('|');
    const enc = new TextEncoder();
    const data = enc.encode(parts);
    const digest = await crypto.subtle.digest('SHA-256', data);
    const hex = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    localStorage.setItem('demoDeviceFingerprintHash', hex);
    return hex;
  } catch {
    return '';
  }
}


