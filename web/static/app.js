// ScamShield Web Command Center - vanilla JS client.
// This file contains ZERO detection/scoring logic. It only renders whatever the
// Flask API (which wraps the real ScamShield engines) returns, plus the real
// research artifacts injected by the server. Risk level and score are never
// recomputed here; the backend's `risk_level` is displayed as-is.

"use strict";

(function () {
  var lastResults = {};   // last parsed analyzer result per input type (for chain)
  var chainItems = [];    // artifacts queued for chain analysis

  function el(id) { return document.getElementById(id); }

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function humanize(key) {
    return String(key).replace(/_/g, " ").trim();
  }

  function humanizeUpper(key) {
    return humanize(key).toUpperCase();
  }

  // Display class is derived from the BACKEND'S risk_level (never recomputed).
  function levelClass(riskLevel) {
    var lvl = String(riskLevel || "").toUpperCase();
    if (lvl === "CRITICAL") return "critical";
    if (lvl === "HIGH") return "high";
    if (lvl === "MEDIUM") return "medium";
    return "low";
  }

  function label(lvl) {
    if (lvl === "CRITICAL" || lvl === "HIGH") return "HIGH RISK";
    if (lvl === "MEDIUM") return "MEDIUM RISK";
    return "LOW RISK";
  }

  // ------------------------------ base ------------------------------

  function section(title, innerHtml) {
    if (!innerHtml) return "";
    return '<div class="section"><div class="section-title">' + esc(title) +
      "</div>" + innerHtml + "</div>";
  }

  function verdictTier(container, cls) {
    container.classList.remove("low", "medium", "high", "critical");
    container.classList.add(cls);
  }

  function renderError(container, json, status) {
    var err = (json && json.error) ? json.error : "Request failed (HTTP " + status + ").";
    var errType = (json && json.error_type) ? json.error_type : "unknown";
    if (!status || isNaN(status) || status === 0) {
      errType = "service_unavailable";
      err = "Analysis service unavailable. Is the ScamShield API running?";
    }
    container.innerHTML =
      '<div class="error-state"><div class="err-type">' + (status === 413
        ? "FILE TOO LARGE" : esc(errType.toUpperCase())) +
      "</div><div>" + esc(err) + "</div></div>";
    verdictTier(container, "low");
  }

  function meterHtml(score, cls) {
    var s = Math.max(0, Math.min(100, Number(score) || 0));
    var r = 53;
    var c = 2 * Math.PI * r;
    var off = c * (1 - s / 100);
    return (
      '<div class="meter ' + cls + '">' +
        '<svg viewBox="0 0 118 118" aria-hidden="true">' +
          '<circle class="track" cx="59" cy="59" r="' + r + '"></circle>' +
          '<circle class="fill" cx="59" cy="59" r="' + r + '" stroke-dasharray="' + c + '" stroke-dashoffset="' + c + '"></circle>' +
        "</svg>" +
        '<div class="meter-core"><div><div class="meter-num">' + s + '</div>' +
        '<div class="meter-unit">/ 100</div></div></div>' +
      "</div>"
    );
  }

  function renderVerdict(result) {
    var score = Number(result.risk_score) || 0;
    var lvl = String(result.risk_level || "LOW").toUpperCase();
    var cls = levelClass(lvl);
    var suspicious = !!result.is_suspicious;

    var scamLine = "";
    if (result.scam_type && String(result.scam_type) !== "safe" && result.input_type !== "chain") {
      scamLine = '<span class="pill neutral">TYPE ' +
        esc(humanizeUpper(result.scam_type)) + "</span>";
    }
    return (
      '<div class="verdict ' + cls + '">' +
        meterHtml(score, cls) +
        '<div class="verdict-body">' +
          '<div class="verdict-label">' + (result.input_type === "chain" ? "CHAIN CLASSIFICATION" : "THREAT ASSESSMENT") + "</div>" +
          '<div class="verdict-status">' + (suspicious ? "THREAT DETECTED" : "NO THREAT DETECTED") + "</div>" +
          '<div class="verdict-fields">' +
            '<span class="pill ' + cls + '">' + lvl + " RISK</span>" +
            '<span class="pill">CONFIDENCE ' + esc(result.confidence) + "%</span>" +
            '<span class="pill">SCORE ' + score + "/100</span>" +
            scamLine +
          "</div>" +
        "</div>" +
      "</div>"
    );
  }

  function indicTitle(inputType) {
    if (inputType === "chain") return "Correlated Indicators";
    if (inputType === "url") return "URL Threat Indicators";
    if (inputType === "qr") return "QR Threat Indicators";
    if (inputType === "upi") return "UPI Threat Indicators";
    return "Threat Indicators";
  }

  // ------------------------------ safety zone ------------------------------

  function zoneClass(zone) {
    var z = String(zone || "").toLowerCase();
    if (z === "green") return "z-green";
    if (z === "red") return "z-red";
    return "z-yellow";
  }

  // Compact, backend-fed safety-zone presentation. All values come from the API
  // (zone / risk_assessment / risk_breakdown); nothing is recomputed here.
  function renderZone(result) {
    if (!result || result.success === false) return "";
    var zone = String(result.zone || "").toLowerCase();
    if (!zone) return "";
    var zc = zoneClass(zone);
    var score = Number(result.risk_score) || 0;
    var label = result.zone_label || humanizeUpper(zone);
    var assessment = result.risk_assessment || {};
    var reasons = assessment.reasons || [];
    var breakD = result.risk_breakdown || {};
    var factors = breakD.factors || [];

    var html = '<div class="zone-block ' + zc + '">' +
      '<div class="zone-head">SAFETY ZONE &mdash; ' + esc(String(zone).toUpperCase()) + "</div>" +
      '<div class="zone-score">' + esc(score) + ' <span class="zone-score-unit">/ 100</span></div>' +
      '<div class="zone-label">' + esc(label) + "</div>" +
      (result.recommended_action ? '<div class="zone-action">' + esc(result.recommended_action) + "</div>" : "") +
      '<div class="zone-meta">RISK ' + esc(result.risk_level || "") +
      " &middot; CONFIDENCE " + esc(result.confidence != null ? result.confidence : "-") + "%</div>" +
      "</div>";

    if (reasons.length) {
      var bullets = reasons.map(function (r) { return "<li>" + esc(r) + "</li>"; }).join("");
      html += section("Why This Is Risky", '<ul class="recs zone-reasons">' + bullets + "</ul>");
    }

    if (factors.length) {
      var rows = factors.map(function (f) {
        var contrib = (typeof f.contribution === "number" && f.contribution > 0)
          ? '<span class="z-contrib">+' + esc(f.contribution) + "</span>" : "";
        var inds = (f.indicators || []).map(function (i) {
          return '<span class="chip">' + esc(humanizeUpper(i)) + "</span>";
        }).join("");
        return '<div class="zfactor"><div class="zfactor-name">' +
          esc(humanize(f.category).toUpperCase()) + contrib + "</div>" +
          (inds ? '<div class="zfactor-inds">' + inds + "</div>" : "") + "</div>";
      }).join("");
      html += section("Risk Factors", '<div class="zfactors">' + rows + "</div>");
      if (breakD.note) {
        html += section("", '<div class="muted zone-note">' + esc(breakD.note) + "</div>");
      }
    }
    return html;
  }

  function renderSummary(result) {
    if (!result.summary) return "";
    return section("Summary", '<div class="summary">' + esc(result.summary) + "</div>");
  }

  function renderIndicators(result) {
    var list = result.indicators || [];
    if (!list.length) return "";
    var chips = list.map(function (i) {
      return '<span class="chip">' + esc(humanizeUpper(i)) + "</span>";
    }).join("");
    return section(indicTitle(result.input_type), '<div class="chips">' + chips + "</div>");
  }

  function renderExplanation(result) {
    var entries = result.explanation || [];
    if (!entries.length) return "";
    var rows = entries.map(function (e) {
      var sev = (e.severity || "low").toLowerCase();
      var scoreTxt = (typeof e.score === "number" && e.score) ? "+" + Math.round(e.score) : "";
      var ev = e.evidence ? ' <span class="ev">[' + esc(e.evidence) + "]</span>" : "";
      if (typeof e === "string") { return '<div class="explainer"><span class="sev low"></span><span class="why">' + esc(e) + "</span></div>"; }
      return '<div class="explainer"><span class="sev ' + sev + '">' + esc(sev) + "</span>" +
        '<span class="sc">' + esc(scoreTxt) + "</span>" +
        '<span class="why">' + esc(e.reason || "") + ev + "</span></div>";
    }).join("");
    return section("Explanation", rows);
  }

  function renderRecommendations(result) {
    var recs = result.recommendations || [];
    if (!recs.length) return "";
    var items = recs.map(function (r) { return "<li>" + esc(r) + "</li>"; }).join("");
    return section("Security Recommendations", '<ul class="recs">' + items + "</ul>");
  }

  // ------------------------------ evidence ------------------------------

  function renderEvidence(result) {
    var ev = result.evidence;
    if (!ev || typeof ev !== "object") return "";
    var rows = [];
    Object.keys(ev).forEach(function (key) {
      var value = ev[key];
      if (value == null || value === "") return;
      var rendered;
      if (Array.isArray(value)) rendered = value.join(", ");
      else if (typeof value === "object") rendered = JSON.stringify(value);
      else rendered = String(value);
      rows.push('<div class="erow"><span class="k">' + esc(humanizeUpper(key)) +
        '</span><span class="v">' + esc(rendered) + "</span></div>");
    });
    if (!rows.length) return "";
    return section("Evidence", '<div class="evidence-grid">' + rows.join("") + "</div>");
  }

  // UPI structured fields row (friendly chip fields)
  function renderUpiFields(result) {
    var parse = null;
    if (result.input_type === "upi") {
      parse = ((result.engine_results || {}).upi || {}).upi_analysis;
      parse = (parse && parse.parse) || null;
    } else if (result.input_type === "qr") {
      var qrEr = (result.engine_results || {}).qr || {};
      if (qrEr.content_type === "upi") parse = ((qrEr.upi_analysis || {}).parse) || null;
      else if (evHasUpi(result.evidence)) parse = result.evidence.upi;
    } else if (result.input_type === "chain") {
      parse = null;
    }
    if (!parse) return "";
    var pairs = [
      ["Payee", parse.payee_name], ["Payee Address", parse.payee_address],
      ["Amount", parse.amount], ["Currency", parse.currency],
      ["Transaction Note", parse.transaction_note],
      ["Merchant Code", parse.merchant_code], ["Transaction Ref", parse.transaction_ref]
    ].filter(function (p) { return p[1] != null && p[1] !== ""; });
    if (!pairs.length) return "";
    var rows = pairs.map(function (p) {
      return '<div class="erow"><span class="k">' + esc(p[0].toUpperCase()) +
        '</span><span class="v">' + esc(p[1]) + "</span></div>";
    }).join("");
    return section("Payment Request Fields", '<div class="evidence-grid">' + rows + "</div>");
  }
  function evHasUpi(evidence) {
    return evidence && typeof evidence.upi === "object" && Object.keys(evidence.upi).length;
  }

  // URL domain/parse detail table
  function renderUrlParse(result) {
    var parse = null;
    if (result.input_type === "url") parse = ((result.engine_results || {}).url || {}).parse;
    else if (result.input_type === "qr" && ((result.engine_results || {}).qr || {}).content_type === "url") {
      parse = ((result.engine_results || {}).qr || {}).url_analysis;
      parse = (parse && parse.parse) || null;
    }
    if (!parse) return "";
    var rows = [
      ["Scheme", parse.scheme], ["Hostname", parse.hostname],
      ["Root Domain", parse.root_domain], ["Subdomains", parse.subdomains],
      ["TLD", parse.tld], ["Path", parse.path], ["Query", parse.query]
    ].filter(function (p) { return p[1] != null && p[1] !== ""; });
    if (!rows.length) return "";
    var html = rows.map(function (p) {
      return '<div class="erow"><span class="k">' + esc(humanizeUpper(p[0])) +
        '</span><span class="v">' + esc(p[1]) + "</span></div>";
    }).join("");
    var label = result.input_type === "qr" ? "Embedded URL Analysis" : "Domain Analysis";
    return section(label, '<div class="evidence-grid">' + html + "</div>");
  }

  // QR decoded content + content type
  function renderQrContent(result) {
    if (result.input_type !== "qr") return "";
    var er = (result.engine_results || {}).qr || {};
    var content = er.decoded_content || result.decoded_content || "";
    var contentHtml = content
      ? '<div class="summary">' + esc(String(content)) + "</div>"
      : "";
    return section("Decoded Content", contentHtml);
  }

  function renderQrNotDecoded(result) {
    if (result.input_type !== "qr") return "";
    var er = (result.engine_results || {}).qr || {};
    var status = er.status || result.status || "";
    if (!result.success) {
      return '<div class="error-state"><div class="err-type">' +
        (status === "NOT DECODED" ? "NO QR CODE DETECTED" : "QR ANALYSIS ERROR") +
        "</div><div>" + esc(er.error || result.error || "The image could not be decoded as a QR code.") +
        "</div></div>";
    }
    if (status === "NOT DECODED") {
      return '<div class="warning">NO QR CODE DETECTED - the image does not contain a decodable QR code.</div>';
    }
    return "";
  }

  function renderQrMulti(result) {
    if (result.input_type !== "qr") return "";
    var er = (result.engine_results || {}).qr || {};
    if (!er.multiple_codes) return "";
    var codes = (er.codes || er.decoded || []);
    var items = codes.map(function (c, i) {
      return '<div class="cstage"><div class="cstage-head"><span class="cs-type">QR CODE ' + (i + 1) + "</span></div>" +
        '<div class="kv"><span class="k">CONTENT</span><span class="v">' + esc(c) + "</span></div></div>";
    }).join("");
    return section("Multiple QR Codes Detected (" + esc(codes.length) + ")", items);
  }

  function renderMl(result) {
    if (result.input_type !== "message") return "";
    var ml = (result.engine_results || {}).ml_analysis;
    if (!ml) return "";
    if (!ml.model_available) {
      return section("Local ML Intelligence", '<span class="muted">ML model unavailable: ' +
        esc(ml.warning || "") + "</span>");
    }
    var pred = String(ml.prediction || "-").toUpperCase();
    var predClass = (pred === "SCAM") ? "high" : "low";
    return section(
      "Local ML Intelligence",
      '<div class="verdict-fields">' +
        '<span class="pill ' + predClass + '">ML: ' + esc(pred) + "</span>" +
        '<span class="pill">SCORE ' + esc(ml.score) + "/100</span>" +
        '<span class="pill">CONF ' + esc(ml.confidence) + "%</span>" +
        '<span class="pill">' + esc(ml.confidence_type || "heuristic") + "</span>" +
      "</div>" +
      '<div class="muted" style="margin-top:8px;">MODEL: ' + esc(ml.model || "-") +
      " | FEATURES: " + esc(ml.features_used || "-") +
      "<br>Local ML signal. It is separate from and does not override the authoritative rule-based risk score, and its probability is a heuristic signal, not a calibrated certainty.</div>"
    );
  }

  function renderWarnings(result) {
    var warnings = result.warnings || [];
    if (!warnings.length) return "";
    return '<div class="warning">' + esc(warnings.join(" / ")) + "</div>";
  }

  // ------------------------------ link purifier ------------------------------

  var LC_IMPACT_LABELS = {
    risk_increasing: ["RISK UP", "high"],
    negative: ["RISK DOWN", "low"],
    neutral: ["NEUTRAL", "medium"]
  };

  function lcImpact(c) {
    var m = LC_IMPACT_LABELS[c.risk_impact] || ["CHANGED", "medium"];
    return '<span class="sev ' + m[1] + '">' + esc(m[0]) + "</span>" +
      '<span class="why">' + esc(c.category + ": " + c.detail) +
      (c.evidence ? ' <span class="ev">[' + esc(c.evidence) + "]</span>" : "") +
      "</span>";
  }

  function renderSafeDestination(result) {
    if (result.input_type !== "link_change") return "";
    var dest = result.destination_analysis || {};
    var safe = result.safe_destination || {};
    var candidates = dest.candidates || [];

    if (!dest.found || !candidates.length) {
      return section("Destination Analysis",
        '<div class="muted">No embedded destination detected. Nothing was invented or reconstructed.</div>') +
        section("Safe Action",
        '<div class="verdict-fields"><span class="pill medium">NO DESTINATION FOUND</span></div>' +
        '<div class="summary">' + esc(safe.safe_action || "No embedded destination detected.") + "</div>");
    }

    var rows = candidates.map(function (c) {
      var status = String(c.status || "UNKNOWN").toUpperCase();
      var cls = status === "VERIFIED" ? "low" : (status === "SUSPICIOUS" ? "high" : "medium");
      var source = String(c.source || "").toLowerCase();
      var sourceLabel = source === "redirect_parameter" ? "REDIRECT PARAMETER"
        : (source === "encoded_url" ? "ENCODED URL" : "NESTED URL");
      if (c.destination_parameter) sourceLabel += " (" + String(c.destination_parameter).toUpperCase() + ")";
      var brand = c.brand_evidence;
      var brandHtml = "";
      if (brand && brand.detected_brand) {
        brandHtml = "<br>DETECTED BRAND: " + esc(String(brand.detected_brand).toUpperCase()) +
          " &middot; SUBMITTED: " + esc(brand.submitted_hostname || "") +
          (brand.expected_domains && brand.expected_domains.length
            ? "<br>EXPECTED OFFICIAL: " + esc(brand.expected_domains.join(", ")) +
              " (evidence only; ScamShield never rewrites the submitted address)" : "");
      }
      return '<div class="explainer"><span class="sev ' + cls + '">' + esc(status) + "</span>" +
        '<span class="why">CANDIDATE DESTINATION: ' + esc(c.url) +
        '<br>SOURCE: ' + esc(sourceLabel) + " &middot; DESTINATION RISK: " + esc(c.risk_score) + "/100 " +
        esc(c.risk_level || "") + (c.is_suspicious ? " &middot; SUSPICIOUS" : " &middot; NOT SUSPICIOUS") +
        brandHtml + "</span></div>";
    }).join("");

    var overall = String(safe.status || "DESTINATION_UNKNOWN").toUpperCase();
    var safeCls = safe.available ? "low" : (overall === "UNSAFE_DESTINATION" ? "high" : "medium");
    var safeHtml = '<div class="verdict-fields"><span class="pill ' + safeCls + '">' +
      esc(overall.replace(/_/g, " ")) + "</span></div>";
    if (safe.available && safe.url) {
      safeHtml += '<div class="evidence-grid"><div class="erow"><span class="k">SAFE DESTINATION (PLAIN TEXT ONLY)</span>' +
        '<span class="v">' + esc(safe.url) + "</span></div></div>";
    }
    safeHtml += '<div class="summary">' + esc(safe.safe_action || safe.reason || "") + "</div>";

    return section("Destination Analysis", rows) + section("Safe Action", safeHtml);
  }

  function renderLinkChange(result) {
    var html = "";
    var mode = result.mode;
    var flags = result.purifier || {};
    var cmp = result.comparison || {};

    var rows = [
      ["Mode", mode === "compare" ? "Change Monitor (baseline vs current)" : "Single Link Inspection"],
      ["Original URL", result.original_url],
      ["Normalized URL", result.normalized_url],
      ["Current URL", result.current_url]
    ];
    if (mode === "compare") rows.push(["Baseline URL", result.baseline_url]);
    rows = rows.filter(function (p) { return p[1] != null && p[1] !== ""; });
    var urlRows = rows.map(function (p) {
      return '<div class="erow"><span class="k">' + esc(p[0].toUpperCase()) +
        '</span><span class="v">' + esc(p[1]) + "</span></div>";
    }).join("");
    html += section("Purified / Inspected Representation", '<div class="evidence-grid">' + urlRows + "</div>");

    var flagRows = [
      ["Redirect Mechanism", flags.redirect_detected],
      ["Nested URL", flags.nested_url_detected],
      ["Encoded Destination", flags.encoded_destination_detected],
      ["Obfuscation", flags.obfuscation_detected]
    ].filter(function (p) { return typeof p[1] === "boolean"; }).map(function (p) {
      var cls = p[1] ? "high" : "low";
      return '<span class="pill ' + cls + '">' + esc(p[0].toUpperCase()) + ": " +
        (p[1] ? "YES" : "NO") + "</span>";
    }).join("");
    if (flagRows) html += section("Purifier Signals", '<div class="verdict-fields">' + flagRows + "</div>");

    var hidden = flags.hidden_components || [];
    if (hidden.length) {
      var items = hidden.map(function (h) { return "<li>" + esc(h) + "</li>"; }).join("");
      html += section("Hidden Components", '<ul class="recs">' + items + "</ul>");
    }

    html += renderSafeDestination(result);

    if (mode === "compare") {
      var changes = cmp.changes || [];
      var rising = (cmp.risk_increasing_changes || []).length;
      var head = '<div class="verdict-fields">' +
        '<span class="pill ' + (changes.length ? "medium" : "low") + '">CHANGES ' + esc(changes.length) + "</span>" +
        '<span class="pill ' + (rising ? "high" : "low") + '">RISK-INCREASING ' + esc(rising) + "</span>";
      if (typeof result.change_impact === "number" && result.change_impact > 0) {
        head += '<span class="pill ' + (result.change_impact >= 40 ? "high" : "medium") +
          '">CHANGE IMPACT ' + esc(result.change_impact) + '/70</span>';
      }
      if (typeof result.risk_delta === "number" && result.risk_delta !== 0) {
        head += '<span class="pill ' + (result.risk_delta > 0 ? "high" : "low") +
          '">RISK DELTA ' + (result.risk_delta > 0 ? "+" : "") + esc(result.risk_delta) + "</span>";
      }
      head += "</div>";
      if (!changes.length) {
        html += section("Link Change Monitor", head +
          '<div class="summary">No structural changes detected between the baseline and the current link.</div>');
      } else {
        var crows = changes.map(function (c) {
          return '<div class="explainer">' + lcImpact(c) + "</div>";
        }).join("");
        html += section("Link Change Monitor", head + crows);
      }
    }
    return html;
  }

  function renderRawToggle(container, result) {
    var wrapper = document.createElement("div");
    wrapper.className = "raw-toggle";
    var btn = document.createElement("button");
    btn.className = "btn";
    btn.type = "button";
    btn.setAttribute("aria-expanded", "false");
    btn.textContent = "View Raw Result";
    var block = document.createElement("div");
    block.className = "raw-block";
    block.hidden = true;
    btn.addEventListener("click", function () {
      var open = block.hidden;
      block.hidden = !open;
      btn.textContent = open ? "Hide Raw Result" : "View Raw Result";
      btn.setAttribute("aria-expanded", open ? "true" : "false");
      if (open) block.textContent = JSON.stringify(result, null, 2);
    });
    wrapper.appendChild(btn);
    wrapper.appendChild(block);
    return wrapper;
  }

  // ------------------------------ chain ------------------------------

  function renderChainFlow(result) {
    var stages = result.stages || [];
    var rels = result.relationships || [];
    if (!stages.length) return "";

    var parts = [];
    stages.forEach(function (s, i) {
      var sus = !!s.is_suspicious;
      var cat = (s.scam_type && s.scam_type !== "safe")
        ? '<span class="cs-cat">' + esc(humanizeUpper(s.scam_type)) + "</span>" : "";
      var ind = (s.indicators || []).map(function (x) {
        return '<span class="chip">' + esc(humanizeUpper(x)) + "</span>";
      }).join("");
      parts.push(
        '<div class="cstage' + (sus ? " sus" : "") + '">' +
          '<div class="cstage-head"><span class="cs-type">STAGE ' + (i + 1) + " - " + esc(s.type || s.label || "artifact").toUpperCase() + "</span>" +
          '<span class="cs-score">' + esc(s.risk_score) + " / 100 " + esc(s.risk_level || "") + "</span>" + cat +
          "</div>" +
          (ind ? '<div class="cs-indicators">' + ind + "</div>" : "") +
        "</div>"
      );

      // relationships that start from this stage
      rels.forEach(function (r) {
        if (Number(r.from_stage) === Number(s.id)) {
          var to = stages.filter(function (x) { return Number(x.id) === Number(r.to_stage); })[0];
          var ev = (r.evidence || []).map(function (e) { return "<div>evidence: " + esc(e) + "</div>"; }).join("");
          parts.push(
            '<div class="cs-midarrow">&#9660; &nbsp;correlates&nbsp; &#9660;</div>' +
            '<div class="cslink"><span class="cl-rel">' + esc(humanizeUpper(r.relation || "relationship")) + "</span>" +
            (r.label ? ' <span class="cl-lab">&mdash; ' + esc(r.label) + "</span>" : "") +
            (r.match_type ? ' <span class="cl-lab">[' + esc(r.match_type) + "]</span>" : "") +
            (typeof r.strength === "number" ? ' <span class="cl-lab">(strength ' + Number(r.strength).toFixed(2) + ")</span>" : "") +
            (to ? ' <span class="cl-lab">to stage ' + esc(to.id) + "</span>" : "") +
            (ev ? '<div class="cl-ev">' + ev + "</div>" : "") +
            "</div>"
          );
        }
      });
      if (i < stages.length - 1) {
        // a plain connecting arrow when no explicit relationship links consecutively
        var hasRel = rels.some(function (r) {
          return Number(r.from_stage) === Number(s.id) && Number(r.to_stage) === Number(stages[i + 1].id);
        });
        if (!hasRel) parts.push('<div class="cs-midarrow">&#9660;</div>');
      }
    });

    return '<div class="chain-vert">' + parts.join("") + "</div>";
  }

  function renderChainFull(result) {
    var cls = result.classification;
    var tier = "none";
    var status = "NO CHAIN RELATIONSHIP DETECTED";
    if (cls === "multi_stage_scam") { tier = "multi"; status = "MULTI-STAGE SCAM DETECTED"; }
    else if (cls === "potential_chain") { tier = "potential"; status = "POTENTIAL CHAIN / INVESTIGATE"; }

    var body =
      renderVerdict(result) +
      renderZone(result) +
      renderSummary(result) +
      (result.chain_pattern ? section("Chain Pattern", '<div class="summary">' +
        esc(humanize(result.chain_pattern).toUpperCase()) + "</div>") : "") +
      renderIndicators(result) +
      renderExplanation(result) +
      renderRecommendations(result);

    return (
      body +
      '<div class="chain-tier ' + tier + '"><div class="chain-tier-head">' +
        '<div class="ttl">MULTI-STAGE SCAM / ATTACK CHAIN</div>' +
        '<span class="pill ' + tier + '">' + esc(status) + "</span></div>" +
        '<div class="muted" style="margin-top:6px;">ScamShield correlates evidence across multiple artifacts instead of evaluating each artifact in isolation.</div>' +
        renderChainFlow(result) +
      "</div>"
    );
  }

  // ------------------------------ research ------------------------------

  function marker() {
    return '<div class="muted" style="margin-top:14px;">Research metrics are generated ' +
      "from the local evaluation dataset and should not be interpreted as " +
      "production-world detection accuracy.</div>";
  }

  function renderResearch(payload) {
    if (!payload) {
      return '<div class="result-block">' +
        '<div class="panel"><div class="panel-title">Research Dashboard</div>' +
        '<div class="warning">Evaluation artifacts not found under models/research/.</div>' +
        '<p class="summary">Run the local evaluation to generate this dashboard:</p>' +
        '<ul class="recs"><li>python -m app.research_eval</li></ul></div>' +
        marker() + "</div>";
    }

    var ds = payload.dataset || {};
    var test = ds.test || {};
    var comparison = payload.comparison || [];

    // Stats row
    var stats = '';
    var stat = function (label, val, sub) {
      return '<div class="rstat"><div class="rstat-label">' + esc(label) + '</div><div class="rstat-val">' + esc(val != null ? val : "-") + (sub ? '</div><div class="rstat-sub">' + esc(sub) + "</div>" : "</div>") + "</div>";
    };
    stats += stat("Test Dataset Size", test.n);
    stats += stat("Scam Samples", test.scam);
    stats += stat("Safe Samples", test.safe);
    stats += stat("Train", (ds.splits || {}).train);
    stats += stat("Validation", (ds.splits || {}).validation);
    stats += stat("Total (deduped)", (ds.splits || {}).total);

    // Comparison table
    var th = ["<tr><th>System</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th><th>FN</th><th>FP</th></tr>"];
    comparison.forEach(function (row) {
      var pct = function (x) { return (x == null ? "-" : String(Math.round(x * 10000) / 100) + "%"); };
      th.push("<tr><td>" + esc(row.system) + "</td>" +
        "<td class='num'>" + pct(row.accuracy) + "</td>" +
        "<td class='num'>" + pct(row.precision) + "</td>" +
        "<td class='num'>" + pct(row.recall) + "</td>" +
        "<td class='num'>" + pct(row.f1) + "</td>" +
        "<td class='num'>" + esc(row.fn_count) + "</td>" +
        "<td class='num'>" + esc(row.fp_count) + "</td></tr>");
    });
    var table = '<div class="panel"><div class="panel-title">Model / System Comparison (Frozen Test Set)</div>' +
      '<table class="mtable"><thead>' + th.shift() + "</thead><tbody>" + th.join("") + "</tbody></table>" +
      '<div class="muted" style="margin-top:8px;">The combined message verdict is rule-driven by design; the local ML signal is kept separate (see Message Intelligence page). Accuracy, precision, recall, F1 shown.</div></div>';

    // Accuracy bars
    var bars = '<div class="panel"><div class="panel-title">Accuracy</div><div class="bars">' +
      comparison.map(function (row) {
        var p = Math.round((row.accuracy || 0) * 10000) / 100;
        return '<div class="bar-row"><span class="bar-label">' + esc(row.system) + '</span>' +
          '<span class="bar-track"><span class="bar-fill" data-w="' + p + '" style="width:0%"></span></span>' +
          '<span class="bar-val">' + p + "%</span></div>";
      }).join("") + "</div></div>";

    // Latency
    var lat = payload.latency || {};
    var engines = lat.engines || {};
    var latRows = Object.keys(engines).map(function (k) {
      var e = engines[k];
      return '<tr><td>' + esc(humanizeUpper(k)) + '</td><td class="num">' + esc(e.mean_ms) + ' ms</td><td class="num">' + esc(e.median_ms) + ' ms</td><td class="num">' + esc(e.min_ms) + " - " + esc(e.max_ms) + " ms</td></tr>";
    }).join("");
    var latency = '<div class="panel"><div class="panel-title">Detection Latency</div>' +
      '<table class="mtable"><thead><tr><th>Engine</th><th>Mean</th><th>Median</th><th>Min - Max</th></tr></thead>' +
      "<tbody>" + latRows + "</tbody></table>" +
      '<div class="muted" style="margin-top:8px;">' + esc(lat.iterations || 20) + " iterations, local run.</div></div>";

    // Leakage
    var leak = payload.leakage || {};
    var leakBlock = '<div class="panel"><div class="panel-title">Dataset Leakage Check</div>';
    if (leak.normalised_total > 0 || leak.exact_total > 0) {
      leakBlock += '<div class="warning"><strong>Potential overlap detected</strong></div>' +
        '<div class="kv" style="margin-top:8px;">' +
        '<span class="k">Normalised overlap</span><span class="v">' + esc(leak.normalised_total) + " text(s)</span>" +
        '<span class="k">Exact overlap</span><span class="v">' + esc(leak.exact_total) + " text(s)</span>" +
        '<span class="k">Overlap type</span><span class="v">' + esc(humanize(leak.overlap_type || "")) + "</span>" +
        '<span class="k">Affected splits</span><span class="v">' + esc((leak.affected_pairs || []).join(", ")) + "</span>" +
        '<span class="k">Leakage-clean subset</span><span class="v">' + esc(leak.clean_subset) + " of 106 test samples retained</span>" +
        "</div>";
      leakBlock += '<div class="muted" style="margin-top:8px;">' + esc(leak.recommendation || "") + "</div>";
      var examples = (leak.examples && leak.examples.exact) || [];
      if (examples.length) {
        var exItems = examples.slice(0, 4).map(function (x) {
          return '<div class="cslink"><span class="cl-lab">' + esc(x.pair) + " &mdash; " + esc(x.text) + "</span></div>";
        }).join("");
        leakBlock += '<div class="section-title" style="border:none;">Example exact overlaps</div>' + exItems;
      }
      leakBlock += '<div class="muted" style="margin-top:8px;">Leakage-clean combined accuracy: ' +
        esc(leak.clean_metrics ? leak.clean_metrics.accuracy : "-") + "</div>";
    } else {
      leakBlock += '<div class="summary">No overlap detected.</div>';
    }
    leakBlock += "</div>";

    // Limitations
    var lims = payload.limitations || [];
    var limHtml = lims.length
      ? section("Research Integrity Notes", '<ul class="recs">' + lims.map(function (l) { return "<li>" + esc(l) + "</li>"; }).join("") + "</ul>")
      : "";

    // Languages + categories (test set distribution)
    var langs = test.languages || {};
    var langRows = Object.keys(langs).map(function (k) {
      return '<tr><td>' + esc(k) + '</td><td class="num">' + esc(langs[k]) + "</td></tr>";
    }).join("");
    var langHtml = langRows ? '<div class="panel"><div class="panel-title">Test Set Languages</div>' +
      '<table class="mtable"><thead><tr><th>Language</th><th>Count</th></tr></thead>' +
      "<tbody>" + langRows + "</tbody></table></div>" : "";

    return '<div class="result-block">' +
      '<div class="rstat-grid">' + stats + "</div>" +
      table + bars + latency + langHtml + leakBlock + limHtml +
      marker() + "</div>";
  }

  function animateAfterInsert(root) {
    var fills = root.querySelectorAll(".bar-fill");
    Array.prototype.forEach.call(fills, function (f) {
      var w = f.getAttribute("data-w");
      setTimeout(function () { f.style.width = w + "%"; }, 50);
    });
    var meters = root.querySelectorAll(".meter .fill");
    Array.prototype.forEach.call(meters, function (m) {
      var off = m.getAttribute("stroke-dashoffset");
      setTimeout(function () { m.style.strokeDashoffset = off; }, 60);
    });
  }

  // ------------------------------ status ------------------------------

  function renderStatus(health) {
    var available = !!health.ml_model_available;
    var rows = [
      ["MESSAGE ENGINE", "Online", "ok"],
      ["URL ENGINE", "Online", "ok"],
      ["QR ENGINE", "Online", "ok"],
      ["UPI ENGINE", "Online", "ok"],
      ["CHAIN ANALYZER", "Online", "ok"],
      ["API", health.status === "ok" ? "Online" : "Offline", health.status === "ok" ? "ok" : "err"],
      ["LOCAL ML", available ? "Available" : "Unavailable", available ? "ok" : "warn"]
    ];
    var list = rows.map(function (r) {
      return '<div class="sys-row"><div><div class="sys-name">' + esc(r[0]) +
        '</div><div class="sys-desc">' + (r[0] === "LOCAL ML" ? "Trained TF-IDF + Logistic Regression model" : "Local deterministic engine") + "</div></div>" +
        '<div class="sys-state dot ' + r[2] + '">' + esc(r[1]) + "</div></div>";
    }).join("");
    return '<div class="result-block"><div class="sys-grid">' + list + "</div>" +
      '<div class="privacy-note" style="margin-top:16px;">All engines run locally and offline. ScamShield does not connect to any external threat-intelligence service.</div></div>';
  }

  // ------------------------------ render orchestration ------------------------------

  function renderResult(container, result) {
    verdictTier(container, "low");
    if (!result || result.success === false) {
      container.innerHTML = "";
      var block = document.createElement("div");
      block.className = "result-block";
      if (result && result.input_type === "qr") {
        block.innerHTML = renderQrNotDecoded(result);
      }
      if (!block.innerHTML) {
        block.innerHTML = '<div class="error-state"><div class="err-type">ANALYSIS UNAVAILABLE</div><div>' +
          esc((result && result.error) || "Analysis failed.") + "</div></div>";
      }
      container.appendChild(block);
      return;
    }

    var root = document.createElement("div");
    root.className = "result-block";
    var html;
    if (result.input_type === "chain") {
      html = renderChainFull(result);
      var raw = renderRawToggle(root, result);
      root.innerHTML = html;
      container.appendChild(root);
      container.appendChild(raw);
      return;
    }

    var isQr = result.input_type === "qr";
    var qrEr = (result.engine_results || {}).qr || {};
    var qrDecoded = isQr && result.success && qrEr.status !== "NOT DECODED";
    if (isQr) html = renderQrNotDecoded(result);
    if (qrDecoded) {
      html += renderVerdict(result);
      html += renderZone(result);
      html += renderQrContent(result);
      if (qrEr.content_type === "url") html += renderUrlParse(result);
      if (qrEr.content_type === "upi") html += renderUpiFields(result);
      html += renderQrMulti(result);
    }
    if (!isQr) html = renderVerdict(result);
    html += renderZone(result);
    if (result.input_type === "upi") html += renderUpiFields(result);
    if (result.input_type === "url") html += renderUrlParse(result);
    if (result.input_type === "link_change") html += renderLinkChange(result);
    html += renderSummary(result);
    html += renderIndicators(result);
    html += renderExplanation(result);
    html += renderRecommendations(result);
    html += renderMl(result);
    html += renderEvidence(result);
    html += renderWarnings(result);
    root.innerHTML = html;
    container.appendChild(root);
    container.appendChild(renderRawToggle(root, result));
  }

  // ------------------------------ fetch helpers ------------------------------

  function postJSON(url, payload, container) {
    container.innerHTML = "";
    container.innerHTML = '<div class="muted">ANALYZING INPUT...</div>';
    fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }).then(function (res) {
      return res.json().then(function (data) { return { status: res.status, data: data }; });
    }).then(function (out) {
      container.innerHTML = "";
      if (out.status !== 200) { renderError(container, out.data, out.status); return; }
      renderResult(container, out.data);
      animateAfterInsert(container);
    }).catch(function () {
      container.innerHTML = "";
      renderError(container, null, 0);
    });
  }

  // ------------------------------ scanners ------------------------------

  function scanText(container, field, inputId, apiPath) {
    var value = el(inputId).value || "";
    if (!value.trim()) {
      container.innerHTML = '<div class="error-state"><div class="err-type">INVALID INPUT</div><div>Enter some text to analyze.</div></div>';
      return;
    }
    var payload = {};
    payload[field] = value;
    postJSON(apiPath, payload, container);
  }

  var qrFile = null;

  function scanLinkChange() {
    var container = el("lc-result");
    var current = (el("lc-current").value || "").trim();
    var baseline = (el("lc-baseline").value || "").trim();
    if (!current) {
      container.innerHTML = '<div class="error-state"><div class="err-type">INVALID INPUT</div><div>Enter a link to inspect (or compare).</div></div>';
      return;
    }
    var payload = baseline
      ? { baseline_url: baseline, current_url: current }
      : { url: current };
    postJSON("/api/analyze/link-change", payload, container);
  }

  function setupQr() {
    var input = el("qr-input");
    var dz = el("dropzone");
    var preview = el("qr-preview");
    var img = el("qr-preview-img");
    var filename = el("qr-filename");
    var filesize = el("qr-filesize");

    function setFile(file) {
      if (!file) return;
      if (file.size > 5 * 1024 * 1024) {
        el("dz-text").textContent = "FILE TOO LARGE (MAX 5 MiB)";
        return;
      }
      qrFile = file;
      filename.textContent = file.name;
      filesize.textContent = "(" + Math.round(file.size / 1024) + " KiB)";
      var reader = new FileReader();
      reader.onload = function (e) { img.src = e.target.result; };
      reader.readAsDataURL(file);
      preview.hidden = false;
      el("dz-text").textContent = "QR IMAGE SELECTED";
    }

    dz.addEventListener("click", function () { input.click(); });
    dz.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); }
    });
    dz.addEventListener("dragover", function (e) { e.preventDefault(); dz.classList.add("drag"); });
    dz.addEventListener("dragleave", function () { dz.classList.remove("drag"); });
    dz.addEventListener("drop", function (e) {
      e.preventDefault();
      dz.classList.remove("drag");
      if (e.dataTransfer.files && e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
    });
    input.addEventListener("change", function () { if (input.files && input.files[0]) setFile(input.files[0]); });
  }

  function scanQr() {
    var container = el("qr-result");
    container.innerHTML = "";
    if (!qrFile) {
      container.innerHTML = '<div class="error-state"><div class="err-type">NO FILE</div><div>Choose or drop a QR image first.</div></div>';
      return;
    }
    container.innerHTML = '<div class="muted">DECODING QR IMAGE LOCALLY...</div>';
    var fd = new FormData();
    fd.append("qr_image", qrFile);
    fetch("/api/analyze/qr", { method: "POST", body: fd }).then(function (res) {
      return res.json().then(function (data) { return { status: res.status, data: data }; });
    }).then(function (out) {
      container.innerHTML = "";
      if (out.status !== 200) { renderError(container, out.data, out.status); return; }
      renderResult(container, out.data);
      animateAfterInsert(container);
    }).catch(function () {
      container.innerHTML = "";
      renderError(container, null, 0);
    });
  }

  // ------------------------------ navigation ------------------------------

  var links = Array.prototype.slice.call(document.querySelectorAll(".nav-link"));
  var pages = Array.prototype.slice.call(document.querySelectorAll(".page"));
  var currentPage = "overview";

  function showPage(name) {
    currentPage = name;
    links.forEach(function (l) {
      l.classList.toggle("is-active", l.getAttribute("data-page") === name);
    });
    pages.forEach(function (p) {
      p.classList.toggle("is-active", p.id === "page-" + name);
    });
    if (name === "chain") renderChainList();
    if (name === "research") renderResearchPage();
    if (name === "status") renderStatusPage();
    if (name === "overview") {
      // re-run ML availability chip on the overview when revisited
      fetchHealthOnly().then(function (h) {
        var chip = el("cap-ml");
        if (chip) chip.textContent = h.ml_model_available ? "Available" : "Unavailable";
      });
    }
    window.scrollTo(0, 0);
    closeSidebar();
  }

  links.forEach(function (l) {
    l.addEventListener("click", function (e) { e.preventDefault(); showPage(l.getAttribute("data-page")); });
  });

  var heroGoto = Array.prototype.slice.call(document.querySelectorAll("[data-goto]"));
  heroGoto.forEach(function (b) {
    b.addEventListener("click", function () { showPage(b.getAttribute("data-goto")); });
  });

  var menuBtn = el("menu-btn");
  var sidebar = el("sidebar");
  var backdrop = el("backdrop");
  var sideClose = el("side-close");
  function openSidebar() { sidebar.classList.add("open"); backdrop.hidden = false; menuBtn.setAttribute("aria-expanded", "true"); }
  function closeSidebar() { sidebar.classList.remove("open"); backdrop.hidden = true; menuBtn.setAttribute("aria-expanded", "false"); }
  menuBtn.addEventListener("click", openSidebar);
  sideClose.addEventListener("click", closeSidebar);
  backdrop.addEventListener("click", closeSidebar);

  // ------------------------------ health ------------------------------

  function fetchHealth() {
    return fetch("/api/health").then(function (r) { return r.json(); });
  }
  function fetchHealthOnly() {
    return fetchHealth().catch(function () { return { status: "err", ml_model_available: false }; });
  }

  function initHealth() {
    fetchHealth().then(function (h) {
      var ok = h.status === "ok";
      [[el("health-dot"), ok], [el("sys-online"), ok]].forEach(function (pair) {
        pair[0].className = "dot " + (ok ? "ok" : "err");
      });
      var hl = el("health-text");
      hl.innerHTML = ok ? ("SYSTEM ONLINE &middot; v" + esc(h.version) + " &middot; LOCAL") : "SYSTEM OFFLINE";
      var ol = el("sys-online-text");
      ol.textContent = ok ? "SYSTEM ONLINE" : "SYSTEM OFFLINE";
      var ml = el("cap-ml");
      if (ml) ml.textContent = h.ml_model_available ? "Available" : "Unavailable";
    }).catch(function () {
      [[el("health-dot"), false], [el("sys-online"), false]].forEach(function (pair) {
        pair[0].className = "dot err";
      });
      el("sys-online-text").textContent = "SYSTEM OFFLINE";
    });
  }

  function renderStatusPage() {
    var root = el("status-root");
    root.innerHTML = '<span class="muted">Checking system status...</span>';
    fetchHealth().then(function (h) {
      root.innerHTML = "";
      root.appendChild(fromHtml(renderStatus(h)));
    }).catch(function () {
      root.innerHTML = "";
      root.appendChild(fromHtml(renderStatus({ status: "err", ml_model_available: false })));
    });
  }

  var researchRabbit = null;
  function renderResearchPage() {
    var root = el("research-root");
    if (researchRabbit !== null) return; // already rendered once
    var payload = window.__RESEARCH__ || null;
    root.innerHTML = "";
    root.appendChild(fromHtml(renderResearch(payload)));
    animateAfterInsert(root);
    researchRabbit = 1;
  }

  function fromHtml(htmlString) {
    var t = document.createElement("template");
    t.innerHTML = htmlString.trim();
    return t.content.firstChild;
  }

  // ------------------------------ chain list ------------------------------

  function lastFor(kind) { return lastResults[kind] || null; }

  function renderChainList() {
    var list = el("chain-stages");
    var name = { message: "MESSAGE", url: "URL", upi: "UPI", qr: "QR" };
    if (!chainItems.length) {
      list.innerHTML = '<div class="chain-empty">No artifacts added yet. Analyze an input on a scanner, then click "Add ... Result" to build a chain.</div>';
      el("chain-scan").disabled = true;
      return;
    }
    list.innerHTML = "";
    chainItems.forEach(function (item, i) {
      var li = document.createElement("div");
      var isSus = !!item.is_suspicious;
      li.className = "chain-list-item" + (isSus ? " suspicious" : "");
      var meta = '<span>' + esc(name[item.input_type] || item.input_type || "STAGE") +
        " | SCORE " + esc(item.risk_score) + "/100 " + esc(item.risk_level || "") +
        (item.scam_type && item.scam_type !== "safe" ? " | " + esc(item.scam_type) : "") + "</span>";
      var rm = '<button class="rm" title="Remove stage" aria-label="Remove stage">&times;</button>';
      li.innerHTML = meta;
      var rmBtn = fromHtml(rm);
      li.appendChild(rmBtn);
      rmBtn.addEventListener("click", function () {
        chainItems.splice(i, 1);
        renderChainList();
      });
      li.style.cssText = "display:flex;gap:10px;align-items:center;background:var(--bg-deep);border:1px solid var(--border);border-left:3px solid var(--border);border-radius:6px;padding:9px 12px;margin-bottom:8px;font-family:var(--mono);font-size:0.78rem;" + (isSus ? "border-left-color:var(--high);" : "");
      rmBtn.style.cssText = "margin-left:auto;background:transparent;border:none;color:var(--text-muted);cursor:pointer;font-size:1.1rem;";
      list.appendChild(li);
    });
    el("chain-scan").disabled = false;
  }

  Array.prototype.forEach.call(document.querySelectorAll(".chain-add"), function (btn) {
    btn.addEventListener("click", function () {
      var kind = btn.getAttribute("data-kind");
      if (!lastResults[kind]) {
        var target = { message: "msg-result", url: "url-result", upi: "upi-result", qr: "qr-result" }[kind];
        el(target).innerHTML = "";
        var t = document.createElement("div"); t.className = "result-block";
        t.innerHTML = '<div class="error-state"><div class="err-type">NO RESULT</div><div>Run a ' +
          esc(kind.toUpperCase()) + " analysis first, then add it to the chain.</div></div>";
        el(target).appendChild(t);
        showPage(kind);
        return;
      }
      if (kind === "qr" && lastResults[kind].input_type !== "qr") { showPage("qr"); return; }
      chainItems.push(lastResults[kind]);
      renderChainList();
    });
  });

  el("chain-scan").addEventListener("click", function () {
    if (!chainItems.length) return;
    postJSON("/api/analyze/chain", { stages: chainItems }, el("chain-result"));
  });

  el("chain-clear").addEventListener("click", function () {
    chainItems = [];
    renderChainList();
    el("chain-result").innerHTML = "";
  });

  // Store the last parsed JSON result per type (for chain building + QR preview logic)
  var _orig = renderResult;
  renderResult = function (container, result) {
    var paneOf = { "msg-result": "message", "url-result": "url", "upi-result": "upi", "qr-result": "qr" };
    var kind = paneOf[container.id];
    if (kind && result && result.success) lastResults[kind] = result;
    _orig(container, result);
  };

  // ------------------------------ wiring ------------------------------

  function setup() {
    el("msg-scan").addEventListener("click", function () {
      scanText(el("msg-result"), "message", "msg-input", "/api/analyze/message");
    });
    el("url-scan").addEventListener("click", function () {
      scanText(el("url-result"), "url", "url-input", "/api/analyze/url");
    });
    el("upi-scan").addEventListener("click", function () {
      scanText(el("upi-result"), "upi", "upi-input", "/api/analyze/upi");
    });
    el("qr-scan").addEventListener("click", scanQr);

    el("lc-scan").addEventListener("click", scanLinkChange);
    el("lc-clear").addEventListener("click", function () {
      el("lc-baseline").value = "";
      el("lc-current").value = "";
      el("lc-result").innerHTML = "";
      el("lc-current").focus();
    });
    el("lc-current").addEventListener("keydown", function (e) {
      if (e.key === "Enter") scanLinkChange();
    });

    el("msg-clear").addEventListener("click", function () { el("msg-input").value = ""; el("msg-count").textContent = "0 characters"; el("msg-result").innerHTML = ""; });
    el("url-clear").addEventListener("click", function () { el("url-input").value = ""; el("url-result").innerHTML = ""; });
    el("upi-clear").addEventListener("click", function () { el("upi-input").value = ""; el("upi-result").innerHTML = ""; });

    el("msg-input").addEventListener("input", function () {
      el("msg-count").textContent = el("msg-input").value.length + " characters";
    });

    // Enter-to-analyze on single-line text fields
    ["url-input", "upi-input"].forEach(function (id) {
      el(id).addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          var kind = id === "url-input" ? "url" : "upi";
          scanText(el(kind + "-result"), kind, id, "/api/analyze/" + kind);
        }
      });
    });

    setupQr();

    var payload = (el("research-payload") || {}).textContent || "null";
    try { window.__RESEARCH__ = JSON.parse(payload); }
    catch (e) { window.__RESEARCH__ = null; }

    showPage("overview");
    initHealth();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setup);
  } else {
    setup();
  }
})();
