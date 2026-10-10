# Tripwire web

React + TypeScript + Vite. The report page (`/r/<id>`), and later the verdict card, the live dashboard and
the paste-a-link box.

```
npm run dev      # http://localhost:5173 ; /r/sample shows the example report
npm test         # contract and route tests (Node's built-in runner, no extra dependencies)
npm run build
npm run lint
```

`src/contract.ts` is the shape of a scan result. It mirrors `analyzer/contract.py`, and both are
checked against `src/sample/report.sample.json`. Change all three together.
