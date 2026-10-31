// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App.jsx";
import { installAuthFetch, bootstrapTokenFromUrl } from "./auth.js";
import "./index.css";

bootstrapTokenFromUrl();   // ?token=… magic-link, stored then stripped from the URL
installAuthFetch();        // attach the bearer token to every /api request, app-wide

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
