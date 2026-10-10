import { useState } from 'react';
import { Camera, Expand, Minimize2, ImageOff, LockKeyhole, LoaderCircle } from 'lucide-react';
import type { ScanDetail } from '../types/scan';
import { approvedScreenshot } from '../api/schema';
import { formatDate } from '../utils/time';

export function ScreenshotPanel({ scan }: { scan: ScanDetail }) {
  const [enlarged, setEnlarged] = useState(false); const [failed, setFailed] = useState(false);
  const shot = scan.screenshot;
  const src = approvedScreenshot(scan.id, shot.path, scan.isRecorded);
  const available = shot.state === 'available' && src && !failed;
  const waiting = ['pending', 'capturing'].includes(shot.state);
  return <aside className={`screenshot-panel ${enlarged ? 'screenshot-enlarged' : ''}`} aria-label="Sandbox capture">
    <div className="screenshot-heading"><Camera size={16} aria-hidden="true" /><h3>Sandbox capture</h3><span className="tiny-tag">IMAGE ONLY</span></div>
    <div className="screenshot-frame">{available ? <img src={src} alt="Captured landing page associated with this scan" onError={() => setFailed(true)} /> : <div className="screenshot-placeholder">{waiting ? <LoaderCircle size={30} className="spin" /> : <ImageOff size={30} />}<h4>{waiting ? shot.state === 'pending' ? 'Waiting for capture' : 'Capturing page' : shot.state === 'expired' ? 'Capture expired' : 'No screenshot available'}</h4><p>{waiting ? 'The image will appear when the analyzer provides it.' : shot.state === 'expired' ? 'This screenshot is no longer available.' : 'The page could not be captured, or capture is not configured.'}</p></div>}</div>
    {scan.isRecorded && <p className="image-demo-label">Illustrative local image · no live capture</p>}
    {available && <button className="button button-small screenshot-toggle" onClick={() => setEnlarged(v => !v)}>{enlarged ? <Minimize2 size={14} /> : <Expand size={14} />}{enlarged ? 'Reduce screenshot' : 'Enlarge screenshot'}</button>}
    <div className="capture-meta">{shot.capturedAt && <p>Captured {formatDate(shot.capturedAt)}<br />Content may have changed.</p>}<p>Source: {scan.isRecorded ? 'Illustrative fixture' : shot.source === 'urlscan' ? 'Approved urlscan fallback' : shot.source === 'tripwire' ? 'Tripwire sandbox' : 'Unavailable'}</p><p><LockKeyhole size={12} aria-hidden="true" />Image only — the website is not open on your device.</p>{shot.description && <p className="capture-description">{shot.description}</p>}</div>
  </aside>;
}
