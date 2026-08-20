import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { createVaultRuntime } from "./runtime";
import "./styles.css";

const rootElement = document.getElementById("root");
if (rootElement === null) throw new Error("The application root is missing.");

const root = createRoot(rootElement);
root.render(<div className="boot-screen"><span className="boot-mark"><img alt="" src="/icons/hasilan-pass-icon.svg" /></span><p>Loading trusted vault core…</p></div>);

void createVaultRuntime()
  .then((runtime) => {
    root.render(<StrictMode><App runtime={runtime} /></StrictMode>);
  })
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "WebAssembly initialization failed.";
    root.render(
      <main className="fatal-screen">
        <div className="brand-lock"><img alt="" src="/icons/hasilan-pass-icon.svg" /></div>
        <h1>Vault core unavailable</h1>
        <p>{message}</p>
        <button className="primary-button" onClick={() => window.location.reload()} type="button">Reload</button>
      </main>,
    );
  });
