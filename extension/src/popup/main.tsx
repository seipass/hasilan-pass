import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { PopupApp } from "./PopupApp";
import "./popup.css";

const root = document.getElementById("root");
if (root === null) throw new Error("Extension popup root is missing.");
createRoot(root).render(<StrictMode><PopupApp /></StrictMode>);

