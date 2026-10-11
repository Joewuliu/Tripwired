import { Dashboard } from './pages/Dashboard.tsx'
import { Home } from './pages/Home.tsx'
import { NotFound } from './pages/NotFound.tsx'
import { ReportPage } from './pages/Report.tsx'
import { parseRoute } from './route.ts'

export default function App() {
  const route = parseRoute(window.location.pathname)
  switch (route.name) {
    case 'home':
      return <Home />
    case 'dashboard':
      return <Dashboard />
    case 'report':
      return <ReportPage id={route.id} />
    default:
      return <NotFound />
  }
}
