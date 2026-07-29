import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";
import "./accessibility.css";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);

// Registers the app-shell service worker so the dashboard can be "installed"
// (Add to Home Screen / desktop install) and still open when offline. Only
// available in a secure context (HTTPS, or http://localhost) per the Service
// Worker spec -- silently does nothing everywhere else, including a plain
// http://<lan-ip> appliance address, which is the common deployment today.
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  });
}
