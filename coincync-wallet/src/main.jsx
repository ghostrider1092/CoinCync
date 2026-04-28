import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";
import "./index.css";

// Prevent Vite HMR from doing full page reloads — show update banner instead
if (import.meta.hot) {
  // Override the default full-reload behavior
  const originalReload = import.meta.hot.data._reload;
  import.meta.hot.on('vite:beforeFullReload', (payload) => {
    // Don't auto-reload — show a notification instead
    const banner = document.getElementById('update-banner');
    if (banner) banner.style.display = 'flex';
    // Prevent the reload
    if (payload) payload.path = '';
  });
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App/>
    </ErrorBoundary>
  </React.StrictMode>
);
