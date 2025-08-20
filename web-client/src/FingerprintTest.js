import React, { useState } from 'react';

const FingerprintTest = () => {
  const [supported, setSupported] = useState(null);
  const [platformAvailable, setPlatformAvailable] = useState(null);
  const [conditionalAvailable, setConditionalAvailable] = useState(null);
  const [message, setMessage] = useState('');

  const check = async () => {
    setMessage('');
    try {
      const hasWebAuthn = typeof window !== 'undefined' && 'PublicKeyCredential' in window;
      setSupported(hasWebAuthn);

      let uvpaa = false;
      let conditional = false;

      if (hasWebAuthn) {
        try {
          uvpaa = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        } catch (e) {
          // ignore
        }
        try {
          conditional = (await window.PublicKeyCredential.isConditionalMediationAvailable?.()) || false;
        } catch (e) {
          // ignore
        }
      }

      setPlatformAvailable(uvpaa);
      setConditionalAvailable(conditional);

      if (!hasWebAuthn) {
        setMessage('WebAuthn is not supported in this browser. Try Chrome or Edge.');
      } else if (!uvpaa) {
        setMessage('No platform authenticator detected or no biometric enrolled. On Windows, enable Windows Hello and enroll a fingerprint.');
      } else {
        setMessage('Platform authenticator detected. You should be able to use your fingerprint.');
      }
    } catch (err) {
      setMessage('Error: ' + (err?.message || String(err)));
    }
  };

  return (
    <div className="mb-8 p-4 border rounded">
      <h2 className="text-xl font-semibold mb-3">Fingerprint / WebAuthn Test</h2>
      <button onClick={check} className="bg-gray-800 text-white px-3 py-2 rounded mb-3">Run Test</button>
      <div className="space-y-1">
        <div><strong>WebAuthn supported:</strong> {supported === null ? '-' : supported ? 'Yes' : 'No'}</div>
        <div><strong>Platform authenticator (fingerprint/Windows Hello) available:</strong> {platformAvailable === null ? '-' : platformAvailable ? 'Yes' : 'No'}</div>
        <div><strong>Conditional mediation available:</strong> {conditionalAvailable === null ? '-' : conditionalAvailable ? 'Yes' : 'No'}</div>
      </div>
      {message && <div className="mt-3 text-sm text-gray-700">{message}</div>}
    </div>
  );
};

export default FingerprintTest;
