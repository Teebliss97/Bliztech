/**
 * BlizTech Academy — CompTIA Security+ Practice Exam
 * app/static/js/practice_exam.js
 *
 * Fetches questions from /practice-exam/questions (certificate-gated endpoint).
 * POSTs completed attempt to /practice-exam/submit.
 */

"use strict";

/* ── State ────────────────────────────────────────────────────────────────── */
let QS          = [];
let DOMAIN_META = {};

let state = {
  current      : 0,
  answers      : {},
  flagged      : new Set(),
  startTime    : null,
  elapsed      : 0,
  timerHandle  : null,
  submitted    : false,
  showAllReview: false,
};

const PASS_PCT      = 75;
const DURATION_SECS = 5400; // 90 minutes

/* ── Boot ─────────────────────────────────────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  fetch("/practice-exam/questions", { credentials: "same-origin" })
    .then(r => {
      if (!r.ok) throw new Error("not_authorised");
      return r.json();
    })
    .then(data => {
      QS          = data.questions;
      DOMAIN_META = data.domain_meta;
      buildStartCards();
    })
    .catch(() => {
      const s = document.getElementById("screen-start");
      if (s) {
        s.innerHTML =
          `<p style="color:#f85149;text-align:center;padding:4rem 0;font-family:'DM Sans',sans-serif;">
             Could not load exam questions.<br>
             <span style="font-size:14px;color:#8b949e;">
               Please make sure you are logged in and have earned your BlizTech certificate.
             </span>
           </p>`;
      }
    });
});

/* ── Start screen cards ───────────────────────────────────────────────────── */
function buildStartCards() {
  const container = document.getElementById("domain-cards-start");
  if (!container) return;

  const counts = {};
  QS.forEach(q => { counts[q.d] = (counts[q.d] || 0) + 1; });

  Object.entries(DOMAIN_META).forEach(([id, meta]) => {
    const card = document.createElement("div");
    card.className = "domain-card";
    card.innerHTML =
      `<div class="dc-pct">${meta.pct}%</div>
       <div class="dc-name">${meta.name}</div>
       <div class="dc-qs">${counts[id] || 0} questions</div>`;
    container.appendChild(card);
  });
}

/* ── Start exam ───────────────────────────────────────────────────────────── */
function startExam() {
  state = {
    current      : 0,
    answers      : {},
    flagged      : new Set(),
    startTime    : Date.now(),
    elapsed      : 0,
    timerHandle  : null,
    submitted    : false,
    showAllReview: false,
  };
  showScreen("exam");
  renderQuestion();
  startTimer();
}

/* ── Timer ────────────────────────────────────────────────────────────────── */
function startTimer() {
  clearInterval(state.timerHandle);
  state.timerHandle = setInterval(() => {
    state.elapsed = Math.floor((Date.now() - state.startTime) / 1000);
    const remaining = Math.max(0, DURATION_SECS - state.elapsed);
    const el = document.getElementById("timer-display");
    if (el) {
      const m = Math.floor(remaining / 60);
      const s = remaining % 60;
      el.textContent = `${m}:${s < 10 ? "0" : ""}${s}`;
      el.classList.toggle("warn", remaining < 600);
    }
    if (remaining <= 0) {
      clearInterval(state.timerHandle);
      finishExam();
    }
  }, 1000);
}

/* ── Render question ──────────────────────────────────────────────────────── */
function renderQuestion() {
  const idx = state.current;
  const q   = QS[idx];
  if (!q) return;

  const answered = state.answers[idx] !== undefined;
  const chosen   = state.answers[idx];
  const dm       = DOMAIN_META[q.d] || {};

  // Progress bar
  document.getElementById("progress-fill").style.width =
    Math.round((idx / QS.length) * 100) + "%";

  // Topbar
  document.getElementById("q-current").textContent     = idx + 1;
  document.getElementById("q-domain-short").textContent = dm.name || "";

  // Flag button
  const flagBtn   = document.getElementById("flag-btn");
  const isFlagged = state.flagged.has(idx);
  flagBtn.textContent = isFlagged ? "Flagged ★" : "Flag for review";
  flagBtn.classList.toggle("flagged", isFlagged);

  // Domain pill + question number
  document.getElementById("q-domain-pill").textContent =
    `Domain ${q.d} — ${dm.name || ""}`;
  document.getElementById("q-num").textContent =
    `Question ${idx + 1} of ${QS.length}`;

  // Scenario box
  const scEl = document.getElementById("scenario-box");
  if (q.scenario) {
    scEl.style.display = "block";
    scEl.textContent   = q.scenario;
  } else {
    scEl.style.display = "none";
  }

  // Question stem
  document.getElementById("q-stem").textContent = q.text;

  // Options
  const list = document.getElementById("options-list");
  list.innerHTML = "";
  q.opts.forEach((opt, i) => {
    const btn = document.createElement("button");
    btn.className = "opt-btn";
    btn.disabled  = answered;

    if (answered) {
      if (i === q.ans)                     btn.classList.add("correct");
      else if (i === chosen)               btn.classList.add("wrong");
      if (i === q.ans && chosen !== q.ans) btn.classList.add("reveal");
    }

    btn.innerHTML =
      `<span class="opt-letter">${String.fromCharCode(65 + i)}</span>
       <span>${opt}</span>`;

    if (!answered) {
      btn.addEventListener("click", () => selectAnswer(i));
    }
    list.appendChild(btn);
  });

  // Explanation
  const expEl = document.getElementById("explanation");
  if (answered) {
    expEl.style.display = "block";
    const ok = chosen === q.ans;
    // CSS classes: .verdict.pass and .verdict.fail (defined in template)
    expEl.innerHTML =
      `<span class="verdict ${ok ? "pass" : "fail"}">${ok ? "Correct." : "Incorrect."}</span>${q.exp}`;
  } else {
    expEl.style.display = "none";
  }

  // Navigation buttons
  document.getElementById("prev-btn").disabled = idx === 0;

  const nextBtn = document.getElementById("next-btn");
  if (idx >= QS.length - 1) {
    nextBtn.textContent = "Submit exam";
    nextBtn.className   = "btn btn-accent btn-sm";
    nextBtn.onclick     = finishExam;
  } else {
    nextBtn.textContent = "Next →";
    nextBtn.className   = "btn btn-outline btn-sm";
    nextBtn.onclick     = nextQ;
  }

  // Answered / flagged counter
  document.getElementById("answered-count").textContent =
    `${Object.keys(state.answers).length} answered · ${state.flagged.size} flagged`;
}

/* ── Answer selection ─────────────────────────────────────────────────────── */
function selectAnswer(i) {
  if (state.answers[state.current] !== undefined) return;
  state.answers[state.current] = i;
  renderQuestion();
}

/* ── Navigation ───────────────────────────────────────────────────────────── */
function prevQ() {
  if (state.current > 0) { state.current--; renderQuestion(); }
}

function nextQ() {
  if (state.current < QS.length - 1) { state.current++; renderQuestion(); }
}

function toggleFlag() {
  const idx = state.current;
  if (state.flagged.has(idx)) state.flagged.delete(idx);
  else state.flagged.add(idx);
  renderQuestion();
}

/* ── Finish & submit ──────────────────────────────────────────────────────── */
function finishExam() {
  if (state.submitted) return;
  state.submitted = true;
  clearInterval(state.timerHandle);

  const correct = QS.filter((q, i) => state.answers[i] === q.ans).length;
  const pct     = Math.round((correct / QS.length) * 100);
  const passed  = pct >= PASS_PCT;

  // POST result to server — fire and forget
  fetch("/practice-exam/submit", {
    method      : "POST",
    credentials : "same-origin",
    headers     : { "Content-Type": "application/json" },
    body        : JSON.stringify({
      answers         : state.answers,
      elapsed_seconds : state.elapsed,
    }),
  }).catch(() => {});

  renderResults(correct, pct, passed);
  showScreen("results");
}

/* ── Render results ───────────────────────────────────────────────────────── */
function renderResults(correct, pct, passed) {
  const elapsed    = Math.min(state.elapsed, DURATION_SECS);
  const timeTaken  = `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`;
  const unanswered = QS.length - Object.keys(state.answers).length;

  // Score hero
  const scoreEl = document.getElementById("result-score");
  scoreEl.textContent = pct + "%";
  scoreEl.className   = `result-score ${passed ? "pass" : "fail"}`;

  const verdictEl = document.getElementById("result-verdict");
  verdictEl.textContent = passed ? "PASS — Well done!" : "FAIL — Keep studying";
  verdictEl.className   = `result-verdict ${passed ? "pass" : "fail"}`;

  document.getElementById("result-sub").textContent =
    `${correct} of ${QS.length} correct · Time: ${timeTaken} · Pass mark: ${PASS_PCT}%`;

  // Stat tiles
  document.getElementById("stats-row").innerHTML =
    tile(correct,             "Correct")    +
    tile(QS.length - correct, "Incorrect")  +
    tile(unanswered,          "Unanswered") +
    tile(timeTaken,           "Time used");

  // Domain breakdown
  const ds = {};
  Object.keys(DOMAIN_META).forEach(id => {
    ds[id] = { correct: 0, total: 0, name: DOMAIN_META[id].name };
  });
  QS.forEach((q, i) => {
    if (!ds[q.d]) return;
    ds[q.d].total++;
    if (state.answers[i] === q.ans) ds[q.d].correct++;
  });

  document.getElementById("domain-breakdown-rows").innerHTML =
    Object.entries(ds).map(([, d]) => {
      const dp  = d.total ? Math.round((d.correct / d.total) * 100) : 0;
      const col = dp >= 75 ? "#3fb950" : dp >= 60 ? "#d29922" : "#f85149";
      return `<div class="db-row">
        <div class="db-name">${d.name}</div>
        <div class="db-track">
          <div class="db-bar" style="width:${dp}%;background:${col}"></div>
        </div>
        <div class="db-pct">${dp}%</div>
      </div>`;
    }).join("");

  // Incorrect question review
  const wrongQs = QS
    .map((q, i) => ({ ...q, idx: i }))
    .filter(q => state.answers[q.idx] !== undefined && state.answers[q.idx] !== q.ans);

  const reviewEl = document.getElementById("review-section");
  if (wrongQs.length === 0) { reviewEl.innerHTML = ""; return; }

  const visible  = state.showAllReview ? wrongQs : wrongQs.slice(0, 8);
  const showMore = !state.showAllReview && wrongQs.length > 8;

  reviewEl.innerHTML =
    `<div class="review-header">
       <div class="review-title">Review — ${wrongQs.length} incorrect</div>
     </div>` +
    visible.map(q => {
      const your   = q.opts[state.answers[q.idx]] || "Unanswered";
      const dmName = DOMAIN_META[q.d] ? DOMAIN_META[q.d].name : "";
      return `<div class="review-item">
        <div class="ri-domain">Q${q.idx + 1} · ${dmName}</div>
        <div class="ri-q">${q.text}</div>
        <div class="ri-answers">
          Your answer: <span class="wrong-ans">${your}</span>
          &nbsp;|&nbsp;
          Correct: <span class="correct-ans">${q.opts[q.ans]}</span>
        </div>
        <div class="ri-exp">${q.exp}</div>
      </div>`;
    }).join("") +
    (showMore
      ? `<button class="btn btn-outline btn-sm" onclick="showAllReview()"
           style="margin-top:8px">
           Show all ${wrongQs.length} incorrect answers
         </button>`
      : "");
}

function showAllReview() {
  state.showAllReview = true;
  const correct = QS.filter((q, i) => state.answers[i] === q.ans).length;
  const pct     = Math.round((correct / QS.length) * 100);
  renderResults(correct, pct, pct >= PASS_PCT);
}

function tile(val, lbl) {
  return `<div class="stat-tile">
            <div class="st-val">${val}</div>
            <div class="st-lbl">${lbl}</div>
          </div>`;
}

/* ── Restart ──────────────────────────────────────────────────────────────── */
function restartExam() {
  clearInterval(state.timerHandle);
  showScreen("start");
}

/* ── Screen switcher ──────────────────────────────────────────────────────── */
function showScreen(name) {
  ["start", "exam", "results"].forEach(id => {
    const el = document.getElementById(`screen-${id}`);
    if (el) el.classList.toggle("active", id === name);
  });
}