import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App.jsx";
import "./index.css";

// Apply the saved theme before first paint to avoid a flash of the wrong theme.
try {
  if (localStorage.getItem("heaven.theme") === "light") {
    document.documentElement.dataset.theme = "light";
  }
} catch { /* localStorage unavailable */ }

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
