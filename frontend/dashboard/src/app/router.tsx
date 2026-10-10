import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { App } from './App';
export function Router() {
  return <BrowserRouter><Routes><Route path="/" element={<App />} /><Route path="/r/:scanId" element={<App />} /><Route path="*" element={<div className="not-found glass-panel"><h1>Page unavailable</h1><p>This Tripwire page could not be found.</p><a className="button" href="/">Back to scans</a></div>} /></Routes></BrowserRouter>;
}
