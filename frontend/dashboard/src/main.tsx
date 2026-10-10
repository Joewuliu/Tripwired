import React from 'react';
import ReactDOM from 'react-dom/client';
import { Router } from './app/router';
import './styles/tokens.css';
import './styles/glass.css';
import './styles/layout.css';

ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><Router /></React.StrictMode>);
