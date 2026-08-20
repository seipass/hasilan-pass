import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { DesktopApp } from "./DesktopApp";
import "./desktop.css";

const root = document.getElementById("root");
if (root === null) throw new Error("Desktop root is missing.");

createRoot(root).render(
  <StrictMode>
    <DesktopApp />
  </StrictMode>,
);
