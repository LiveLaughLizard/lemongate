// LemonGate playground: streams chat completions and embeddings from the gateway's
// own /v1 API using the console session (cookie + X-CSRF-Token header).
(function () {
  "use strict";

  var STORE_KEY = "lg-playground-settings";

  function csrf() {
    var m = document.querySelector('meta[name="csrf-token"]');
    if (m && m.content) return m.content;
    try { return JSON.parse(document.body.getAttribute("hx-headers") || "{}")["X-CSRF-Token"] || ""; } catch (e) { return ""; }
  }

  function loadSettings() {
    try { return JSON.parse(localStorage.getItem(STORE_KEY) || "{}") || {}; } catch (e) { return {}; }
  }
  function saveSettings(s) {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(s)); } catch (e) {}
  }

  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  // Minimal, safe markdown: everything is HTML-escaped first, then a small set of
  // constructs (fenced code, inline code, bold, italic, headings, lists) is styled.
  function inline(s) {
    var parts = s.split(/(`[^`\n]+`)/g);
    return parts.map(function (p) {
      if (p.length > 1 && p[0] === "`" && p[p.length - 1] === "`") return "<code class=\"rounded bg-base-300/60 px-1 py-0.5\">" + p.slice(1, -1) + "</code>";
      return p.replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>").replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
    }).join("");
  }
  function renderMarkdown(src) {
    var text = esc(src || "");
    var out = [];
    var blocks = text.split(/```/);
    for (var i = 0; i < blocks.length; i++) {
      var b = blocks[i];
      if (i % 2 === 1) {
        var nl = b.indexOf("\n");
        var lang = nl >= 0 ? b.slice(0, nl).trim() : "";
        var code = nl >= 0 ? b.slice(nl + 1) : b;
        code = code.replace(/\n$/, "");
        out.push("<div class=\"md-code relative my-2\"><div class=\"flex items-center justify-between rounded-t-field bg-neutral px-3 py-1 text-[11px] text-neutral-content/70\"><span>" +
          (lang || "code") + "</span><button type=\"button\" class=\"md-copy hover:text-neutral-content\">Copy</button></div>" +
          "<pre class=\"m-0! rounded-t-none! bg-neutral! text-neutral-content\"><code>" + code + "</code></pre></div>");
        continue;
      }
      var lines = b.split("\n");
      var list = null;
      var para = [];
      var flushPara = function () { if (para.length) { out.push("<p>" + para.map(inline).join("<br>") + "</p>"); para = []; } };
      var flushList = function () { if (list) { out.push("<" + list.tag + " class=\"" + (list.tag === "ul" ? "list-disc" : "list-decimal") + " ml-5 my-1\">" + list.items.map(function (it) { return "<li>" + inline(it) + "</li>"; }).join("") + "</" + list.tag + ">"); list = null; } };
      for (var j = 0; j < lines.length; j++) {
        var ln = lines[j];
        var h = ln.match(/^(#{1,4})\s+(.*)$/);
        var ul = ln.match(/^\s*[-*]\s+(.*)$/);
        var ol = ln.match(/^\s*\d+[.)]\s+(.*)$/);
        if (h) { flushPara(); flushList(); out.push("<p class=\"font-semibold " + (h[1].length <= 2 ? "text-base" : "") + "\">" + inline(h[2]) + "</p>"); }
        else if (ul || ol) {
          flushPara();
          var tag = ul ? "ul" : "ol";
          if (!list || list.tag !== tag) { flushList(); list = { tag: tag, items: [] }; }
          list.items.push((ul || ol)[1]);
        } else if (ln.trim() === "") { flushPara(); flushList(); }
        else { flushList(); para.push(ln); }
      }
      flushPara(); flushList();
    }
    return out.join("");
  }

  function fmtMoney(v) {
    if (v == null || isNaN(v)) return "—";
    if (v === 0) return "$0.00";
    if (v < 0.0001) return "<$0.0001";
    if (v < 0.01) return "$" + v.toFixed(5);
    return "$" + v.toFixed(4);
  }
  function fmtNum(v) { return v == null ? "—" : Number(v).toLocaleString(); }

  function shellQuote(s) { return "'" + s.replace(/'/g, "'\\''") + "'"; }
  function pyLiteral(v, indent) {
    indent = indent || "";
    var next = indent + "    ";
    if (v === null || v === undefined) return "None";
    if (v === true) return "True";
    if (v === false) return "False";
    if (typeof v === "number") return String(v);
    if (typeof v === "string") return JSON.stringify(v);
    if (Array.isArray(v)) {
      if (!v.length) return "[]";
      return "[\n" + v.map(function (x) { return next + pyLiteral(x, next); }).join(",\n") + ",\n" + indent + "]";
    }
    var keys = Object.keys(v);
    return "{" + keys.map(function (k) { return JSON.stringify(k) + ": " + pyLiteral(v[k], indent); }).join(", ") + "}";
  }

  function component(data) {
    var saved = loadSettings();
    var chat = data.chat || [], emb = data.embedding || [];
    var pick = function (list, want, fallback) {
      if (want && list.some(function (m) { return m.name === want; })) return want;
      if (fallback && list.some(function (m) { return m.name === fallback; })) return fallback;
      return list.length ? list[0].name : "";
    };
    return {
      tab: data.tab || "chat",
      chatModels: chat,
      embModels: emb,
      baseURL: data.base_url,
      model: pick(chat, data.model, saved.model),
      system: saved.system != null ? saved.system : "You are a helpful assistant.",
      temperature: saved.temperature != null ? saved.temperature : 0.7,
      maxTokens: saved.maxTokens != null ? saved.maxTokens : 1024,
      topP: saved.topP != null ? saved.topP : 1,
      stream: saved.stream != null ? saved.stream : true,
      input: "",
      messages: [],
      busy: false,
      controller: null,
      last: null,
      codeTab: "curl",
      showSettings: false,
      // embeddings
      embModel: pick(emb, data.model, saved.embModel),
      embInput: "The quick brown fox jumps over the lazy dog.",
      embSplit: false,
      embBusy: false,
      embResult: null,
      embError: "",

      init: function () {
        var self = this;
        ["model", "system", "temperature", "maxTokens", "topP", "stream", "embModel"].forEach(function (k) {
          self.$watch(k, function () { self.persist(); });
        });
        this.$el.addEventListener("click", function (e) {
          var btn = e.target.closest && e.target.closest(".md-copy");
          if (btn) {
            var pre = btn.closest(".md-code").querySelector("code");
            window.lgCopy(pre.textContent);
          }
        });
      },
      persist: function () {
        saveSettings({ model: this.model, system: this.system, temperature: Number(this.temperature), maxTokens: Number(this.maxTokens),
          topP: Number(this.topP), stream: this.stream, embModel: this.embModel });
      },
      get current() { var n = this.model; return this.chatModels.find(function (m) { return m.name === n; }) || null; },
      get currentEmb() { var n = this.embModel; return this.embModels.find(function (m) { return m.name === n; }) || null; },
      md: renderMarkdown,
      money: fmtMoney,
      n: fmtNum,

      reset: function () {
        if (this.busy) this.stop();
        this.messages = [];
        this.last = null;
        this.$nextTick(function () { var t = document.getElementById("pg-input"); if (t) t.focus(); });
      },
      suggest: function (text) { this.input = text; this.send(); },
      onKey: function (e) {
        if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); this.send(); }
      },
      scroll: function () {
        var box = this.$refs.scroller;
        if (!box) return;
        var near = box.scrollHeight - box.scrollTop - box.clientHeight < 160;
        if (near) box.scrollTop = box.scrollHeight;
      },
      requestBody: function (extra) {
        var msgs = [];
        if (this.system && this.system.trim()) msgs.push({ role: "system", content: this.system });
        this.messages.forEach(function (m) { if (!m.error && (m.role === "user" || (m.role === "assistant" && m.content))) msgs.push({ role: m.role, content: m.content }); });
        var body = { model: this.model, messages: msgs };
        var t = parseFloat(this.temperature), mt = parseInt(this.maxTokens, 10), tp = parseFloat(this.topP);
        if (!isNaN(t)) body.temperature = t;
        if (!isNaN(mt) && mt > 0) body.max_tokens = mt;
        if (!isNaN(tp) && tp < 1) body.top_p = tp;
        if (extra) Object.keys(extra).forEach(function (k) { body[k] = extra[k]; });
        return body;
      },

      send: async function () {
        var text = (this.input || "").trim();
        if (!text || this.busy || !this.model) return;
        this.messages.push({ role: "user", content: text });
        this.input = "";
        var reply = { role: "assistant", content: "", reasoning: "", pending: true, meta: null, error: "" };
        this.messages.push(reply);
        reply = this.messages[this.messages.length - 1]; // reactive proxy
        this.busy = true;
        this.$nextTick(() => { this.$refs.scroller && (this.$refs.scroller.scrollTop = this.$refs.scroller.scrollHeight); });
        var body = this.requestBody(this.stream ? { stream: true, stream_options: { include_usage: true } } : null);
        var price = this.current;
        var started = performance.now(), ttft = null, usage = null;
        this.controller = new AbortController();
        var stopped = false;
        try {
          var res = await fetch("/v1/chat/completions", {
            method: "POST", credentials: "same-origin", signal: this.controller.signal,
            headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
            body: JSON.stringify(body),
          });
          var hdr = {
            requestId: res.headers.get("x-lemongate-request-id") || "",
            model: res.headers.get("x-lemongate-model") || body.model,
            deployment: res.headers.get("x-lemongate-deployment") || "",
            cache: res.headers.get("x-lemongate-cache") || "",
            cost: res.headers.get("x-lemongate-cost"),
          };
          if (!res.ok) {
            var errText = await res.text();
            var msg = "Request failed (" + res.status + ")";
            try { var ej = JSON.parse(errText); if (ej && ej.error && ej.error.message) msg = ej.error.message; } catch (e) { if (errText) msg = errText.slice(0, 400); }
            reply.error = msg;
            reply.meta = { status: res.status, requestId: hdr.requestId, latency: Math.round(performance.now() - started) };
            return;
          }
          var ctype = res.headers.get("content-type") || "";
          if (this.stream && ctype.indexOf("text/event-stream") >= 0 && res.body) {
            var reader = res.body.getReader();
            var decoder = new TextDecoder();
            var buf = "";
            for (;;) {
              var r = await reader.read();
              if (r.done) break;
              buf += decoder.decode(r.value, { stream: true });
              var idx;
              while ((idx = buf.indexOf("\n")) >= 0) {
                var line = buf.slice(0, idx).trim();
                buf = buf.slice(idx + 1);
                if (line.indexOf("data:") !== 0) continue;
                var payload = line.slice(5).trim();
                if (!payload || payload === "[DONE]") continue;
                var chunk;
                try { chunk = JSON.parse(payload); } catch (e) { continue; }
                if (chunk.error) { reply.error = chunk.error.message || "Stream error"; continue; }
                if (chunk.usage) usage = chunk.usage;
                var ch = (chunk.choices || [])[0];
                if (ch && ch.delta) {
                  var piece = ch.delta.content || "";
                  var think = ch.delta.reasoning_content || ch.delta.reasoning || "";
                  if ((piece || think) && ttft === null) ttft = Math.round(performance.now() - started);
                  if (piece) reply.content += piece;
                  if (think) reply.reasoning += think;
                  if (ch.finish_reason) reply.finish = ch.finish_reason;
                  this.$nextTick(() => this.scroll());
                }
              }
            }
          } else {
            var j = await res.json();
            var c0 = (j.choices || [])[0] || {};
            reply.content = (c0.message && c0.message.content) || c0.text || "";
            reply.reasoning = (c0.message && (c0.message.reasoning_content || c0.message.reasoning)) || "";
            reply.finish = c0.finish_reason;
            usage = j.usage || null;
          }
          var latency = Math.round(performance.now() - started);
          var cost = hdr.cost != null && hdr.cost !== "" ? parseFloat(hdr.cost) : null;
          if (cost === null && usage && price) cost = (usage.prompt_tokens || 0) * price.input_cost_per_m / 1e6 + (usage.completion_tokens || 0) * price.output_cost_per_m / 1e6;
          reply.meta = {
            requestId: hdr.requestId, model: hdr.model, deployment: hdr.deployment, cache: hdr.cache,
            prompt: usage ? usage.prompt_tokens : null, completion: usage ? usage.completion_tokens : null,
            total: usage ? (usage.total_tokens || (usage.prompt_tokens || 0) + (usage.completion_tokens || 0)) : null,
            latency: latency, ttft: ttft, cost: cost,
            tps: usage && usage.completion_tokens && latency > (ttft || 0) ? (usage.completion_tokens / ((latency - (ttft || 0)) / 1000)) : null,
          };
          this.last = reply.meta;
        } catch (e) {
          if (e && e.name === "AbortError") { stopped = true; reply.stopped = true; reply.meta = { latency: Math.round(performance.now() - started), ttft: ttft }; }
          else reply.error = "Network error: " + (e && e.message ? e.message : e);
        } finally {
          reply.pending = false;
          this.busy = false;
          this.controller = null;
          if (!reply.content && !reply.error && !stopped) reply.error = "The model returned an empty response.";
          this.$nextTick(() => this.scroll());
        }
      },
      stop: function () { if (this.controller) this.controller.abort(); },
      retry: function (i) {
        if (this.busy) return;
        // Drop the failed/last reply and resend the preceding user turn.
        var prev = this.messages[i - 1];
        if (!prev || prev.role !== "user") return;
        this.messages.splice(i - 1, 2);
        this.input = prev.content;
        this.send();
      },
      copyMsg: function (m) { window.lgCopy(m.content); },

      // ---- code snippets ----
      get snippetBody() {
        var b = this.requestBody();
        if (!b.messages.length || b.messages[b.messages.length - 1].role !== "user") b.messages.push({ role: "user", content: this.input || "Hello!" });
        return b;
      },
      get curlSnippet() {
        var b = this.snippetBody;
        b.stream = !!this.stream;
        return "curl " + this.baseURL + "/chat/completions \\\n" +
          "  -H \"Authorization: Bearer $LEMONGATE_API_KEY\" \\\n" +
          "  -H \"Content-Type: application/json\" \\\n" +
          "  -d " + shellQuote(JSON.stringify(b, null, 2));
      },
      get pythonSnippet() {
        var b = this.snippetBody;
        var args = ["    model=" + JSON.stringify(b.model), "    messages=" + pyLiteral(b.messages, "    ")];
        if (b.temperature != null) args.push("    temperature=" + b.temperature);
        if (b.max_tokens != null) args.push("    max_tokens=" + b.max_tokens);
        if (b.top_p != null) args.push("    top_p=" + b.top_p);
        if (this.stream) args.push("    stream=True");
        var s = "import os\nfrom openai import OpenAI\n\nclient = OpenAI(\n    base_url=" + JSON.stringify(this.baseURL) + ",\n    api_key=os.environ[\"LEMONGATE_API_KEY\"],\n)\n\n";
        s += (this.stream ? "stream" : "resp") + " = client.chat.completions.create(\n" + args.join(",\n") + ",\n)\n";
        s += this.stream ? "for chunk in stream:\n    if chunk.choices:\n        print(chunk.choices[0].delta.content or \"\", end=\"\", flush=True)\n" : "print(resp.choices[0].message.content)\n";
        return s;
      },
      get jsSnippet() {
        var b = this.snippetBody;
        if (this.stream) b.stream = true;
        var body = JSON.stringify(b, null, 2).replace(/\n/g, "\n");
        var s = "import OpenAI from \"openai\";\n\nconst client = new OpenAI({\n  baseURL: " + JSON.stringify(this.baseURL) + ",\n  apiKey: process.env.LEMONGATE_API_KEY,\n});\n\n";
        s += "const " + (this.stream ? "stream" : "resp") + " = await client.chat.completions.create(" + body + ");\n";
        s += this.stream ? "for await (const chunk of stream) {\n  process.stdout.write(chunk.choices[0]?.delta?.content ?? \"\");\n}\n" : "console.log(resp.choices[0].message.content);\n";
        return s;
      },
      get snippet() { return this.codeTab === "python" ? this.pythonSnippet : this.codeTab === "js" ? this.jsSnippet : this.curlSnippet; },
      openCode: function () { this.$refs.codeDlg.showModal(); },

      // ---- embeddings ----
      embed: async function () {
        if (this.embBusy || !this.embModel) return;
        var raw = (this.embInput || "").trim();
        if (!raw) return;
        var inputs = this.embSplit ? raw.split(/\n+/).map(function (s) { return s.trim(); }).filter(Boolean) : [raw];
        this.embBusy = true; this.embError = ""; this.embResult = null;
        var started = performance.now();
        try {
          var res = await fetch("/v1/embeddings", {
            method: "POST", credentials: "same-origin",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
            body: JSON.stringify({ model: this.embModel, input: inputs.length === 1 ? inputs[0] : inputs }),
          });
          var latency = Math.round(performance.now() - started);
          var txt = await res.text();
          var j = null;
          try { j = JSON.parse(txt); } catch (e) {}
          if (!res.ok) { this.embError = (j && j.error && j.error.message) || ("Request failed (" + res.status + ")"); return; }
          var price = this.currentEmb;
          var usage = (j && j.usage) || {};
          var cost = res.headers.get("x-lemongate-cost");
          cost = cost != null && cost !== "" ? parseFloat(cost) : (price ? (usage.prompt_tokens || 0) * price.input_cost_per_m / 1e6 : null);
          var vectors = ((j && j.data) || []).map(function (d, i) {
            var v = d.embedding || [];
            var norm = Math.sqrt(v.reduce(function (a, x) { return a + x * x; }, 0));
            var maxAbs = v.slice(0, 64).reduce(function (a, x) { return Math.max(a, Math.abs(x)); }, 0) || 1;
            return {
              input: inputs[d.index != null ? d.index : i] || "", dims: v.length, norm: norm,
              head: v.slice(0, 8).map(function (x) { return typeof x === "number" ? x.toFixed(5) : String(x); }),
              bars: v.slice(0, 64).map(function (x) { return { h: Math.max(4, Math.abs(x) / maxAbs * 100), neg: x < 0 }; }),
            };
          });
          var sims = [];
          if (vectors.length > 1 && j.data.length > 1) {
            var a = j.data[0].embedding, na = vectors[0].norm;
            for (var k = 1; k < j.data.length; k++) {
              var bv = j.data[k].embedding, dot = 0;
              for (var q = 0; q < Math.min(a.length, bv.length); q++) dot += a[q] * bv[q];
              sims.push({ input: vectors[k].input, sim: na && vectors[k].norm ? dot / (na * vectors[k].norm) : 0 });
            }
          }
          this.embResult = { vectors: vectors, sims: sims, tokens: usage.prompt_tokens || usage.total_tokens || 0, latency: latency, cost: cost,
            requestId: res.headers.get("x-lemongate-request-id") || "" };
        } catch (e) {
          this.embError = "Network error: " + (e && e.message ? e.message : e);
        } finally {
          this.embBusy = false;
        }
      },
    };
  }

  window.lgPlaygroundInit = function () {
    var root = document.getElementById("pg-root");
    var tpl = document.getElementById("pg-tpl");
    var dataEl = document.getElementById("pg-data");
    if (!root || !tpl || !dataEl) return;
    var data = {};
    try { data = JSON.parse(dataEl.textContent || "{}"); } catch (e) {}
    var mount = function () {
      window.lgPlayground = function () { return component(data); };
      root.innerHTML = "";
      root.appendChild(tpl.content.cloneNode(true));
    };
    if (window.Alpine) { mount(); }
    else { document.addEventListener("alpine:init", mount, { once: true }); }
  };
  window.lgPlaygroundInit();
})();
