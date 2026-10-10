import { Component, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { HomePage } from '../pages/HomePage';

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 1000, gcTime: 300000, refetchOnWindowFocus: true } } });
class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    if (this.state.failed) return <main className="not-found glass-panel"><h1>PhishFinder needs a refresh</h1><p>The interface could not display this page. Your server scans are unaffected.</p><button className="button" onClick={() => window.location.reload()}>Reload page</button></main>;
    return this.props.children;
  }
}
export function App() { return <ErrorBoundary><QueryClientProvider client={queryClient}><HomePage /></QueryClientProvider></ErrorBoundary>; }
