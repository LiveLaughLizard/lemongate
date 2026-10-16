// LemonGate console glue: theme, toasts, modal, confirm dialog, command palette, charts.
(function () {
  "use strict";

  // ---- theme ----
  window.lgSetTheme = function (t) {
    document.documentElement.setAttribute("data-theme", t);
    try { localStorage.setItem("lg-theme", t); } catch (e) {}
    syncThemeToggles();
    document.querySelectorAll("canvas[data-chart]").forEach(function (c) { renderChart(c, true); });
  };
  function syncThemeToggles() {
    var dark = document.documentElement.getAttribute("data-theme") === "lemon-night";
    document.querySelectorAll(".theme-toggle").forEach(function (el) { el.checked = dark; });
  }

  // ---- clipboard ----
  window.lgCopy = function (text) {
    navigator.clipboard.writeText(text).then(function () {
      window.dispatchEvent(new CustomEvent("toast", { detail: { kind: "success", message: "Copied to clipboard" } }));
    });
  };

  // ---- Alpine components ----
  document.addEventListener("alpine:init", function () {
    Alpine.data("toasts", function () {
      return {
        items: [], n: 0,
        push: function (d) {
          var id = ++this.n, self = this;
          this.items.push({ id: id, kind: d.kind || "info", message: d.message || d.value || "" });
          setTimeout(function () { self.dismiss(id); }, d.kind === "error" ? 7000 : 3500);
        },
        dismiss: function (id) { this.items = this.items.filter(function (t) { return t.id !== id; }); },
      };
    });

    Alpine.data("palette", function (nav) {
      var flat = [];
      (nav || []).forEach(function (g) { (g.Items || []).forEach(function (it) { flat.push({ Label: it.Label, Href: it.Href, Group: g.Label || "Overview" }); }); });
      return {
        q: "", sel: 0, open: false, items: flat,
        get results() {
          var q = this.q.toLowerCase().trim();
          return q ? this.items.filter(function (i) { return (i.Label + " " + i.Group).toLowerCase().indexOf(q) >= 0; }) : this.items;
        },
        show: function () { this.q = ""; this.sel = 0; this.open = true; this.$refs.dlg.showModal(); var self = this; setTimeout(function () { self.$refs.q.focus(); }, 30); },
        move: function (d) { var n = this.results.length; if (n) this.sel = (this.sel + d + n) % n; },
        go: function () { var r = this.results[this.sel]; if (r) { this.$refs.dlg.close(); htmx.ajax("GET", r.Href, { target: "body", swap: "innerHTML" }).then(function () { history.pushState({}, "", r.Href); }); } },
      };
    });
  });

  // ---- charts ----
  function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  function palette() {
    return ["--color-primary", "--color-secondary", "--color-accent", "--color-info", "--color-success", "--color-warning", "--color-error"].map(cssVar)
      .concat(["#a78bfa", "#f472b6", "#2dd4bf", "#fb923c"]);
  }
  function alpha(color, a) { return "color-mix(in oklch, " + color + " " + Math.round(a * 100) + "%, transparent)"; }
  function fmt(kind, v) {
    if (kind === "money") { if (v === 0) return "$0"; var a = Math.abs(v); return "$" + (a < 0.01 ? Number(v.toPrecision(2)).toString() : v.toLocaleString(undefined, { maximumFractionDigits: 2 })); }
    if (kind === "ms") return v.toLocaleString() + " ms";
    if (kind === "pct") return v.toFixed(1) + "%";
    return Number(v).toLocaleString(undefined, { maximumFractionDigits: 2 });
  }
  function renderChart(canvas, force) {
    if (!window.Chart) return;
    if (canvas._chart) { if (!force) return; canvas._chart.destroy(); }
    var spec;
    try { spec = JSON.parse(canvas.getAttribute("data-chart")); } catch (e) { return; }
    var colors = palette();
    var text = cssVar("--color-base-content");
    var grid = alpha(text, 0.08);
    var type = spec.type || "line";
    var datasets = (spec.datasets || []).map(function (ds, i) {
      var c = colors[(ds.colorIndex != null ? ds.colorIndex : i) % colors.length];
      var base = { label: ds.label, data: ds.data, borderWidth: 2, borderColor: c, pointRadius: 0, pointHoverRadius: 4, tension: 0.35 };
      if (type === "line") { base.fill = spec.stacked ? true : (i === 0 ? "origin" : false); base.backgroundColor = alpha(c, 0.18); }
      else if (type === "doughnut") { base.backgroundColor = ds.data.map(function (_, j) { return colors[j % colors.length]; }); base.borderColor = cssVar("--color-base-100"); base.borderWidth = 3; }
      else { base.backgroundColor = alpha(c, 0.85); base.borderRadius = 6; base.borderWidth = 0; base.maxBarThickness = 36; }
      return base;
    });
    var horizontal = spec.horizontal === true;
    var opts = {
      responsive: true, maintainAspectRatio: false, animation: { duration: 500 },
      interaction: { mode: "index", intersect: false },
      indexAxis: horizontal ? "y" : "x",
      plugins: {
        legend: { display: spec.legend !== false && (datasets.length > 1 || type === "doughnut"), position: type === "doughnut" ? "right" : "top", align: "end",
          labels: { color: text, usePointStyle: true, boxWidth: 8, font: { family: "Inter Variable" } } },
        tooltip: { backgroundColor: cssVar("--color-neutral"), titleColor: cssVar("--color-neutral-content"), bodyColor: cssVar("--color-neutral-content"),
          padding: 10, cornerRadius: 10, displayColors: datasets.length > 1,
          callbacks: { label: function (ctx) { var v = ctx.parsed && typeof ctx.parsed === "object" ? (horizontal ? ctx.parsed.x : ctx.parsed.y) : ctx.parsed; return (ctx.dataset.label ? ctx.dataset.label + ": " : "") + fmt(spec.format, v); } } },
      },
    };
    if (type !== "doughnut") {
      var valueAxis = { beginAtZero: true, stacked: !!spec.stacked, grid: { color: grid }, border: { display: false },
        ticks: { color: alpha(text, 0.6), callback: function (v) { return fmt(spec.format, v); }, maxTicksLimit: 6 } };
      var catAxis = { stacked: !!spec.stacked, grid: { display: false }, border: { display: false }, ticks: { color: alpha(text, 0.6), maxRotation: 0, autoSkipPadding: 16 } };
      opts.scales = horizontal ? { x: valueAxis, y: catAxis } : { x: catAxis, y: valueAxis };
    } else {
      opts.cutout = "68%";
    }
    canvas._chart = new Chart(canvas, { type: type, data: { labels: spec.labels || [], datasets: datasets }, options: opts });
  }
  function initCharts(root) { (root || document).querySelectorAll("canvas[data-chart]").forEach(function (c) { renderChart(c, false); }); }

  // ---- htmx wiring ----
  // htmx.min.js is deferred just before this script and initializes on
  // DOMContentLoaded, so configuring it here takes effect before it processes the page.
  if (window.htmx) {
    htmx.config.responseHandling = [
      { code: "204", swap: false },
      { code: "[23]..", swap: true },
      { code: "422", swap: true },
      { code: "[45]..", swap: false, error: true },
    ];
    htmx.config.scrollBehavior = "smooth";
    htmx.config.defaultSettleDelay = 0;
    // No history snapshots: they would copy pages (including a freshly issued API
    // key or invite link in the modal) into browser storage. Back/forward re-fetches
    // the full page instead, so it must not be requested as an htmx partial.
    htmx.config.historyCacheSize = 0;
    htmx.config.historyRestoreAsHxRequest = false;
  }
  // Purge snapshots written before the cache was disabled (older htmx versions used localStorage).
  ["sessionStorage", "localStorage"].forEach(function (s) {
    try { window[s].removeItem("htmx-history-cache"); } catch (e) {}
  });

  document.addEventListener("DOMContentLoaded", function () {
    syncThemeToggles();
    initCharts();
  });

  document.addEventListener("htmx:load", function (e) { initCharts(e.target); syncThemeToggles(); });

  document.addEventListener("htmx:afterSwap", function (e) {
    var t = e.detail.target;
    if (t && t.id === "modal-body") {
      var box = document.getElementById("modal-box");
      var size = t.querySelector("[data-modal-size]");
      box.classList.remove("max-w-2xl", "max-w-4xl", "max-w-lg", "max-w-6xl");
      box.classList.add(size ? size.getAttribute("data-modal-size") : "max-w-2xl");
      var m = document.getElementById("modal");
      if (!m.open) m.showModal();
      var first = t.querySelector("input:not([type=hidden]):not([readonly]), select, textarea");
      if (first) setTimeout(function () { first.focus(); }, 50);
    }
  });

  document.addEventListener("close-modal", function () { var m = document.getElementById("modal"); if (m && m.open) m.close(); });

  // Empty the modal once it has closed (after the fade-out) so secrets shown in it
  // do not linger in the DOM. "close" does not bubble, hence the capture listener.
  document.addEventListener("close", function (e) {
    var m = e.target;
    if (!m || m.id !== "modal") return;
    setTimeout(function () {
      var body = document.getElementById("modal-body");
      if (!m.open && body && m.contains(body)) body.replaceChildren();
    }, 300);
  }, true);

  document.addEventListener("htmx:responseError", function (e) {
    var xhr = e.detail.xhr;
    if (xhr && !xhr.getResponseHeader("HX-Trigger")) {
      window.dispatchEvent(new CustomEvent("toast", { detail: { kind: "error", message: "Request failed (" + xhr.status + ")" } }));
    }
  });
  document.addEventListener("htmx:sendError", function () {
    window.dispatchEvent(new CustomEvent("toast", { detail: { kind: "error", message: "Network error — is the server reachable?" } }));
  });

  // Pretty confirm dialog for hx-confirm.
  document.addEventListener("htmx:confirm", function (e) {
    if (!e.detail.question) return;
    e.preventDefault();
    var dlg = document.getElementById("confirm-dialog");
    if (!dlg) { if (confirm(e.detail.question)) e.detail.issueRequest(true); return; }
    document.getElementById("confirm-text").textContent = e.detail.question;
    var ok = document.getElementById("confirm-ok"), cancel = document.getElementById("confirm-cancel");
    var cleanup = function () { ok.onclick = null; cancel.onclick = null; dlg.close(); };
    ok.onclick = function () { cleanup(); e.detail.issueRequest(true); };
    cancel.onclick = cleanup;
    dlg.showModal();
  });
})();
