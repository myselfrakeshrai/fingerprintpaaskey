import { useEffect, useRef } from 'react';
import { Application } from '@splinetool/runtime';

export default function SplineScene({ sceneUrl, className }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    if (!canvasRef.current) return;
    if (!sceneUrl || typeof sceneUrl !== 'string') return;
    // Load only .splinecode assets to avoid runtime parsing errors
    const looksValid = sceneUrl.includes('.splinecode');
    if (!looksValid) return;
    const app = new Application(canvasRef.current);
    try {
      app.load(sceneUrl).catch((e) => {
        // Swallow load errors to avoid crashing the page
        // eslint-disable-next-line no-console
        console.warn('[Spline] load failed:', e?.message || e);
      });
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn('[Spline] runtime error:', e?.message || e);
    }
    return () => {
      // Removing the canvas detaches listeners. If dispose() becomes available, call it here.
    };
  }, [sceneUrl]);

  return <canvas ref={canvasRef} className={className} />;
}
