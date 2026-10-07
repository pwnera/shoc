import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import { App } from "./App";
import { forgetReload, reloadForNewBuild } from "./lib/stale";
import "./index.css";

// A redeploy drops the hashed chunks this tab was built against: reload once onto the new build.
window.addEventListener("vite:preloadError", (event) => {
  if (reloadForNewBuild()) event.preventDefault();
});
setTimeout(forgetReload, 10_000);

// Before RFC 0028 the console kept a bearer token in storage. It keeps no credential now: drop the old one.
try {
  localStorage.removeItem("shoc.token");
} catch {
  /* storage blocked: nothing was kept */
}

const root = document.getElementById("root");
if (!root) throw new Error("no #root element");
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
