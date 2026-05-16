/* ═══════════════════════════════════════════════════════════════════════════
 * BlizTech Academy — CompTIA Security+ Practice Exam Frontend
 * app/static/js/practice_exam.js
 *
 * Powers practice_exam.html — three-screen UI:
 *   1) Start screen    — set selector + domain summary
 *   2) Exam screen     — 90 questions, timer, flag-for-review, navigation
 *   3) Results screen  — score, verdict, stats, domain breakdown, review
 *
 * Endpoints used:
 *   GET  /practice-exam/questions       — Set 1 questions (no answers)
 *   GET  /practice-exam/questions/set2  — Set 2 questions (no answers)
 *   POST /practice-exam/submit          — Auth only: grade + save attempt
 *   POST /practice-exam/grade           — Public: grade only, no save
 *   POST /practice-exam/review          — Public: per-question answers + exps
 *
 * Auth detection: reads <body data-authenticated="true|false">
 *   - Logged in → POST /submit, results show "View past attempts" button
 *   - Anonymous → POST /grade,  results show "Sign in to save score" button
 *
 * CSP-safe — no eval, no string-injected handlers. Inline onclick="..." in the
 * template is supported because 'unsafe-inline' is in script-src, but this
 * file also wires the same handlers via addEventListener for safety.
 * ═══════════════════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  // ════════════════════════════════════════════════════════════════════════
  //  CONFIG
  // ════════════════════════════════════════════════════════════════════════

  var DEFAULT_DURATION_SECS = 90 * 60;   // 90 minutes
  var TIMER_WARN_SECS       = 5 * 60;    // turn timer red under 5 minutes
  var PASS_PCT              = 75;

  // ════════════════════════════════════════════════════════════════════════
  //  STATE
  // ════════════════════════════════════════════════════════════════════════

  var state = {
    selectedSet:    1,                  // 1 or 2 (toggled on start screen)
    activeSet:      null,               // set actually being taken
    questions:      [],                 // [{ d, text, opts, scenario? }]
    domainMeta:     {},                 // { 1: { name, pct }, ... }
    total:          0,
    durationSecs:   DEFAULT_DURATION_SECS,
    answers:        {},                 // { "0": 2, "1": 1, ... }
    flagged:        {},                 // { "0": true, ... }
    currentIdx:     0,
    startedAt:      null,
    timerId:        null,
    finished:       false,
    reviewItems:    [],                 // populated after /review
  };

  // ════════════════════════════════════════════════════════════════════════
  //  HELPERS
  // ════════════════════════════════════════════════════════════════════════

  function $(id) { return document.getElementById(id); }

  function show(screenId) {
    ['screen-start', 'screen-exam', 'screen-results'].forEach(function (id) {
      var el = $(id);
      if (!el) return;
      if (id === screenId) {
        el.classList.add('active');
      } else {
        el.classList.remove('active');
      }
    });
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function formatTime(seconds) {
    if (seconds < 0) seconds = 0;
    var m = Math.floor(seconds / 60);
    var s = seconds % 60;
    return (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s;
  }

  function elapsedSeconds() {
    if (!state.startedAt) return 0;
    return Math.floor((Date.now() - state.startedAt) / 1000);
  }

  function isAuthenticated() {
    var body = document.body;
    if (!body) return false;
    return body.getAttribute('data-authenticated') === 'true';
  }

  function answeredCount() {
    return Object.keys(state.answers).length;
  }

  function flaggedCount() {
    return Object.keys(state.flagged).length;
  }

  function letter(idx) {
    return String.fromCharCode(65 + idx); // 0 → A, 1 → B, etc.
  }

  // Build a query-string-friendly URL with the current set
  function questionsUrlFor(setNum) {
    return setNum === 2
      ? '/practice-exam/questions/set2'
      : '/practice-exam/questions';
  }

  // ════════════════════════════════════════════════════════════════════════
  //  START SCREEN
  // ════════════════════════════════════════════════════════════════════════

  function renderDomainCardsStart() {
    var container = $('domain-cards-start');
    if (!container) return;

    container.innerHTML = '';
    // Render in domain number order for consistency
    var keys = Object.keys(state.domainMeta).sort(function (a, b) {
      return parseInt(a, 10) - parseInt(b, 10);
    });

    if (keys.length === 0) {
      // Fall back to static 5-domain card set if domain_meta not yet loaded
      var fallback = [
        { id: 1, name: 'General Security Concepts',              pct: 12 },
        { id: 2, name: 'Threats, Vulnerabilities & Mitigations', pct: 22 },
        { id: 3, name: 'Security Architecture',                  pct: 18 },
        { id: 4, name: 'Security Operations',                    pct: 28 },
        { id: 5, name: 'Security Program Management',            pct: 20 },
      ];
      fallback.forEach(function (d) {
        container.appendChild(buildDomainCard(d.pct, d.name, ''));
      });
      return;
    }

    keys.forEach(function (k) {
      var d = state.domainMeta[k];
      container.appendChild(buildDomainCard(d.pct, d.name, ''));
    });
  }

  function buildDomainCard(pct, name, qLine) {
    var card = document.createElement('div');
    card.className = 'domain-card';

    var pctEl = document.createElement('div');
    pctEl.className = 'dc-pct';
    pctEl.textContent = pct + '%';

    var nameEl = document.createElement('div');
    nameEl.className = 'dc-name';
    nameEl.textContent = name;

    card.appendChild(pctEl);
    card.appendChild(nameEl);

    if (qLine) {
      var qsEl = document.createElement('div');
      qsEl.className = 'dc-qs';
      qsEl.textContent = qLine;
      card.appendChild(qsEl);
    }

    return card;
  }

  // Exposed to inline onclick in template
  function selectSet(setNum) {
    state.selectedSet = setNum;
    var card1 = $('set1-card');
    var card2 = $('set2-card');
    if (card1) card1.classList.toggle('selected', setNum === 1);
    if (card2) card2.classList.toggle('selected', setNum === 2);
  }

  // ════════════════════════════════════════════════════════════════════════
  //  LOAD QUESTIONS + START EXAM
  // ════════════════════════════════════════════════════════════════════════

  function loadQuestions(setNum) {
    return fetch(questionsUrlFor(setNum), { credentials: 'same-origin' })
      .then(function (resp) {
        if (!resp.ok) throw new Error('Failed to load questions: ' + resp.status);
        return resp.json();
      })
      .then(function (data) {
        state.questions    = data.questions || [];
        state.domainMeta   = data.domain_meta || {};
        state.total        = data.total || state.questions.length;
        state.durationSecs = data.duration_secs || DEFAULT_DURATION_SECS;
        state.activeSet    = data.set || setNum;

        // Reset per-attempt state
        state.answers     = {};
        state.flagged     = {};
        state.currentIdx  = 0;
        state.finished    = false;
        state.reviewItems = [];

        return data;
      });
  }

  // Exposed to inline onclick in template
  function startExam() {
    var startBtn = document.querySelector('#screen-start .btn-accent');
    if (startBtn) {
      startBtn.disabled = true;
      startBtn.textContent = 'Loading…';
    }

    loadQuestions(state.selectedSet)
      .then(function () {
        show('screen-exam');
        renderQuestion();
        startTimer();
      })
      .catch(function (err) {
        console.error(err);
        if (startBtn) {
          startBtn.disabled = false;
          startBtn.textContent = 'Begin exam';
        }
        alert('Could not load the exam questions. Please refresh and try again.');
      });
  }

  // ════════════════════════════════════════════════════════════════════════
  //  EXAM SCREEN — RENDER QUESTION
  // ════════════════════════════════════════════════════════════════════════

  function renderQuestion() {
    var idx = state.currentIdx;
    var q = state.questions[idx];
    if (!q) return;

    var qCurrent = $('q-current');
    if (qCurrent) qCurrent.textContent = String(idx + 1);

    // Domain pill + short label
    var domainId   = q.d;
    var domainInfo = state.domainMeta[domainId] || { name: '', pct: 0 };

    var domainShort = $('q-domain-short');
    if (domainShort) {
      domainShort.textContent = 'Domain ' + domainId + ' · ' + domainInfo.name;
    }

    var domainPill = $('q-domain-pill');
    if (domainPill) {
      domainPill.textContent = 'D' + domainId + ' · ' + domainInfo.name;
    }

    var qNum = $('q-num');
    if (qNum) qNum.textContent = 'Question ' + (idx + 1);

    // Scenario (optional — exam route doesn't include scenarios today,
    // but render if a question ever ships with q.scenario)
    var scenarioBox = $('scenario-box');
    if (scenarioBox) {
      if (q.scenario) {
        scenarioBox.textContent = q.scenario;
        scenarioBox.style.display = '';
      } else {
        scenarioBox.style.display = 'none';
      }
    }

    // Stem
    var qStem = $('q-stem');
    if (qStem) qStem.textContent = q.text;

    // Options
    var optsList = $('options-list');
    if (optsList) {
      optsList.innerHTML = '';
      var chosen = state.answers[String(idx)];

      q.opts.forEach(function (optText, optIdx) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'opt-btn';
        if (chosen === optIdx) btn.classList.add('selected');

        var letterEl = document.createElement('div');
        letterEl.className = 'opt-letter';
        letterEl.textContent = letter(optIdx);

        var textEl = document.createElement('div');
        textEl.className = 'opt-text';
        textEl.textContent = optText;

        btn.appendChild(letterEl);
        btn.appendChild(textEl);

        btn.addEventListener('click', function () {
          state.answers[String(idx)] = optIdx;
          renderQuestion();    // re-render to show selection state
          updateAnsweredCount();
          updateProgress();
        });

        optsList.appendChild(btn);
      });
    }

    // Hide explanation box (only used in inline-feedback mode — not used
    // during live exam since explanations are revealed on results screen)
    var expBox = $('explanation');
    if (expBox) expBox.style.display = 'none';

    // Flag button state
    var flagBtn = $('flag-btn');
    if (flagBtn) {
      if (state.flagged[String(idx)]) {
        flagBtn.classList.add('flagged');
        flagBtn.textContent = 'Flagged';
      } else {
        flagBtn.classList.remove('flagged');
        flagBtn.textContent = 'Flag for review';
      }
    }

    // Prev / Next buttons
    var prevBtn = $('prev-btn');
    var nextBtn = $('next-btn');
    if (prevBtn) prevBtn.disabled = (idx === 0);

    if (nextBtn) {
      var isLast = (idx === state.total - 1);
      nextBtn.textContent = isLast ? 'Submit exam →' : 'Next →';
      // Keep enabled either way — submit on last
    }

    updateAnsweredCount();
    updateProgress();
  }

  function updateAnsweredCount() {
    var counter = $('answered-count');
    if (!counter) return;
    var ans = answeredCount();
    var flg = flaggedCount();
    counter.textContent = ans + ' answered · ' + flg + ' flagged';
  }

  function updateProgress() {
    var bar = $('progress-fill');
    if (!bar) return;
    var pct = state.total ? ((state.currentIdx + 1) / state.total) * 100 : 0;
    bar.style.width = pct + '%';
  }

  // ════════════════════════════════════════════════════════════════════════
  //  EXAM SCREEN — NAVIGATION + FLAG
  // ════════════════════════════════════════════════════════════════════════

  function prevQ() {
    if (state.currentIdx > 0) {
      state.currentIdx--;
      renderQuestion();
    }
  }

  function nextQ() {
    if (state.finished) return;

    if (state.currentIdx >= state.total - 1) {
      // Already on last question → submit
      confirmAndSubmit();
      return;
    }
    state.currentIdx++;
    renderQuestion();
  }

  function toggleFlag() {
    var key = String(state.currentIdx);
    if (state.flagged[key]) {
      delete state.flagged[key];
    } else {
      state.flagged[key] = true;
    }
    renderQuestion();
  }

  function confirmAndSubmit() {
    var unanswered = state.total - answeredCount();
    var flg = flaggedCount();

    var msgParts = [];
    if (unanswered > 0) {
      msgParts.push('You have ' + unanswered + ' unanswered question'
        + (unanswered === 1 ? '' : 's') + '.');
    }
    if (flg > 0) {
      msgParts.push(flg + ' question' + (flg === 1 ? ' is' : 's are')
        + ' flagged for review.');
    }
    msgParts.push('Submit your exam?');

    if (!window.confirm(msgParts.join(' '))) return;
    submitExam(false);
  }

  // ════════════════════════════════════════════════════════════════════════
  //  TIMER
  // ════════════════════════════════════════════════════════════════════════

  function startTimer() {
    var timerEl = $('timer-display');
    if (!timerEl) return;

    state.startedAt = Date.now();

    function tick() {
      if (state.finished) {
        clearInterval(state.timerId);
        return;
      }
      var remaining = state.durationSecs - elapsedSeconds();
      timerEl.textContent = formatTime(remaining);
      timerEl.classList.toggle('warn', remaining <= TIMER_WARN_SECS);
      if (remaining <= 0) {
        clearInterval(state.timerId);
        submitExam(true);
      }
    }

    tick();
    state.timerId = setInterval(tick, 1000);
  }

  // ════════════════════════════════════════════════════════════════════════
  //  SUBMIT
  // ════════════════════════════════════════════════════════════════════════

  function submitExam(timedOut) {
    if (state.finished) return;
    state.finished = true;
    if (state.timerId) clearInterval(state.timerId);

    var payload = {
      answers: state.answers,
      elapsed_seconds: elapsedSeconds(),
      set: state.activeSet,
    };

    var primary = isAuthenticated()
      ? '/practice-exam/submit'
      : '/practice-exam/grade';

    fetch(primary, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    })
      .then(function (resp) {
        if (resp.status === 401) {
          // Session expired mid-exam — gracefully fall back to anonymous grade
          return fetch('/practice-exam/grade', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify(payload),
          }).then(function (r) { return r.json(); });
        }
        if (!resp.ok) throw new Error('Submit failed: ' + resp.status);
        return resp.json();
      })
      .then(function (gradeResult) {
        // Fetch the review payload (correct answers + explanations)
        return fetchReview(payload).then(function (reviewData) {
          showResults(gradeResult, reviewData, timedOut);
        });
      })
      .catch(function (err) {
        console.error('Exam submit error:', err);
        // Show whatever we have, no review
        showResults({
          correct: 0,
          total: state.total,
          score_pct: 0,
          passed: false,
          set: state.activeSet,
          saved: false,
          login_required: !isAuthenticated(),
          error: true,
        }, null, timedOut);
      });
  }

  function fetchReview(payload) {
    return fetch('/practice-exam/review', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ answers: payload.answers, set: payload.set }),
    })
      .then(function (resp) {
        if (!resp.ok) throw new Error('Review fetch failed');
        return resp.json();
      })
      .catch(function (err) {
        console.warn('Review unavailable:', err);
        return null;
      });
  }

  // ════════════════════════════════════════════════════════════════════════
  //  RESULTS SCREEN
  // ════════════════════════════════════════════════════════════════════════

  function showResults(result, reviewData, timedOut) {
    state.reviewItems = (reviewData && reviewData.items) ? reviewData.items : [];

    show('screen-results');

    var passed = !!result.passed;
    var scorePct = (typeof result.score_pct === 'number') ? result.score_pct : 0;

    // ── Hero score ─────────────────────────────────────────────────────
    var scoreEl   = $('result-score');
    var verdictEl = $('result-verdict');
    var subEl     = $('result-sub');

    if (scoreEl) {
      scoreEl.textContent = scorePct + '%';
      scoreEl.classList.remove('pass', 'fail');
      scoreEl.classList.add(passed ? 'pass' : 'fail');
    }
    if (verdictEl) {
      verdictEl.textContent = passed ? 'Pass' : 'Fail';
      verdictEl.classList.remove('pass', 'fail');
      verdictEl.classList.add(passed ? 'pass' : 'fail');
    }
    if (subEl) {
      if (result.error) {
        subEl.textContent = 'We could not reach the server to grade your exam. Please refresh and try again.';
      } else {
        var parts = [
          result.correct + ' of ' + result.total + ' correct',
          'Pass mark: ' + PASS_PCT + '%',
        ];
        if (timedOut) parts.push('time expired');
        subEl.textContent = parts.join(' · ');
      }
    }

    // ── Stats tiles ────────────────────────────────────────────────────
    renderStatsRow(result, timedOut);

    // ── Domain breakdown ───────────────────────────────────────────────
    renderDomainBreakdown();

    // ── Review section ─────────────────────────────────────────────────
    renderReview();

    // ── Actions (anonymous: show "Sign in to save score" button) ───────
    updateResultsActions(result);
  }

  function renderStatsRow(result, timedOut) {
    var row = $('stats-row');
    if (!row) return;

    var elapsed = elapsedSeconds();
    var mm = Math.floor(elapsed / 60);
    var ss = elapsed % 60;
    var timeStr = (mm < 10 ? '0' : '') + mm + ':' + (ss < 10 ? '0' : '') + ss;

    var wrong   = result.total - result.correct;
    var skipped = state.total - answeredCount();

    var tiles = [
      { val: String(result.correct),  lbl: 'Correct' },
      { val: String(wrong),           lbl: 'Wrong' },
      { val: String(skipped),         lbl: 'Skipped' },
      { val: timeStr,                 lbl: timedOut ? 'Time (expired)' : 'Time taken' },
    ];

    row.innerHTML = '';
    tiles.forEach(function (t) {
      var tile = document.createElement('div');
      tile.className = 'stat-tile';
      var val = document.createElement('div');
      val.className = 'st-val';
      val.textContent = t.val;
      var lbl = document.createElement('div');
      lbl.className = 'st-lbl';
      lbl.textContent = t.lbl;
      tile.appendChild(val);
      tile.appendChild(lbl);
      row.appendChild(tile);
    });
  }

  function renderDomainBreakdown() {
    var container = $('domain-breakdown-rows');
    if (!container) return;

    container.innerHTML = '';

    if (!state.reviewItems.length) {
      // No review data — render placeholder rows from domain meta
      var keys = Object.keys(state.domainMeta).sort(function (a, b) {
        return parseInt(a, 10) - parseInt(b, 10);
      });
      keys.forEach(function (k) {
        var d = state.domainMeta[k];
        container.appendChild(buildDomainRow(d.name, 0, 0));
      });
      return;
    }

    // Tally correct/total per domain
    var byDomain = {};
    state.reviewItems.forEach(function (item) {
      var did = item.domain;
      if (!byDomain[did]) {
        byDomain[did] = {
          name: item.domain_name || ('Domain ' + did),
          correct: 0,
          total: 0,
        };
      }
      byDomain[did].total += 1;
      if (item.is_correct) byDomain[did].correct += 1;
    });

    Object.keys(byDomain)
      .sort(function (a, b) { return parseInt(a, 10) - parseInt(b, 10); })
      .forEach(function (did) {
        var stats = byDomain[did];
        container.appendChild(buildDomainRow(stats.name, stats.correct, stats.total));
      });
  }

  function buildDomainRow(name, correct, total) {
    var pct = total ? Math.round((correct / total) * 100) : 0;

    var row = document.createElement('div');
    row.className = 'db-row';

    var nameEl = document.createElement('div');
    nameEl.className = 'db-name';
    nameEl.textContent = name;

    var track = document.createElement('div');
    track.className = 'db-track';

    var bar = document.createElement('div');
    bar.className = 'db-bar';
    // Colour the bar green at pass-mark, red below it, accent (brand) at 100
    var barColor;
    if (pct >= 90) {
      barColor = 'var(--accent)';
    } else if (pct >= PASS_PCT) {
      barColor = 'var(--green)';
    } else {
      barColor = 'var(--danger)';
    }
    bar.style.backgroundColor = barColor;
    bar.style.width = pct + '%';
    track.appendChild(bar);

    var pctEl = document.createElement('div');
    pctEl.className = 'db-pct';
    pctEl.textContent = pct + '%';

    row.appendChild(nameEl);
    row.appendChild(track);
    row.appendChild(pctEl);
    return row;
  }

  function renderReview() {
    var section = $('review-section');
    if (!section) return;

    section.innerHTML = '';

    if (!state.reviewItems.length) {
      // No review data (anonymous fallback failed, or fetch error)
      var emptyHeader = document.createElement('div');
      emptyHeader.className = 'review-header';
      var emptyTitle = document.createElement('div');
      emptyTitle.className = 'review-title';
      emptyTitle.textContent = 'Review unavailable';
      emptyHeader.appendChild(emptyTitle);
      section.appendChild(emptyHeader);
      var note = document.createElement('div');
      note.className = 'result-sub';
      note.style.textAlign = 'left';
      note.style.padding = '12px 0';
      note.textContent = 'Could not load per-question review. Try refreshing.';
      section.appendChild(note);
      return;
    }

    var wrongItems = state.reviewItems.filter(function (it) { return !it.is_correct; });

    var header = document.createElement('div');
    header.className = 'review-header';
    var title = document.createElement('div');
    title.className = 'review-title';
    title.textContent = wrongItems.length
      ? 'Review wrong answers (' + wrongItems.length + ')'
      : 'All correct — no items to review';
    header.appendChild(title);
    section.appendChild(header);

    if (!wrongItems.length) return;

    wrongItems.forEach(function (item) {
      section.appendChild(buildReviewItem(item));
    });
  }

  function buildReviewItem(item) {
    var wrap = document.createElement('div');
    wrap.className = 'review-item';

    var dom = document.createElement('div');
    dom.className = 'ri-domain';
    dom.textContent = 'Q' + (item.idx + 1) + ' · Domain ' + item.domain
      + (item.domain_name ? ' — ' + item.domain_name : '');
    wrap.appendChild(dom);

    var q = document.createElement('div');
    q.className = 'ri-q';
    q.textContent = item.text;
    wrap.appendChild(q);

    var ans = document.createElement('div');
    ans.className = 'ri-answers';

    if (item.chosen_idx === null || item.chosen_idx === undefined) {
      var skipped = document.createElement('div');
      skipped.innerHTML = '<span class="wrong-ans">Your answer:</span> '
        + '<em style="color:var(--text-dim)">Not answered</em>';
      ans.appendChild(skipped);
    } else {
      var wrong = document.createElement('div');
      wrong.innerHTML = '<span class="wrong-ans">Your answer:</span> '
        + letter(item.chosen_idx) + '. ' + escapeHtml(item.opts[item.chosen_idx]);
      ans.appendChild(wrong);
    }

    var correct = document.createElement('div');
    correct.style.marginTop = '3px';
    correct.innerHTML = '<span class="correct-ans">Correct:</span> '
      + letter(item.correct_idx) + '. ' + escapeHtml(item.opts[item.correct_idx]);
    ans.appendChild(correct);

    wrap.appendChild(ans);

    if (item.explanation) {
      var exp = document.createElement('div');
      exp.className = 'ri-exp';
      exp.textContent = item.explanation;
      wrap.appendChild(exp);
    }

    return wrap;
  }

  function escapeHtml(s) {
    if (s === undefined || s === null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function updateResultsActions(result) {
    // Find the .results-actions container (already in the template).
    // Replace its contents to swap the "Back to lessons" button based on
    // anonymous vs authenticated.
    var actions = document.querySelector('#screen-results .results-actions');
    if (!actions) return;

    actions.innerHTML = '';

    // Primary action: try another exam
    var retry = document.createElement('button');
    retry.type = 'button';
    retry.className = 'btn btn-accent';
    retry.textContent = 'Try another exam';
    retry.addEventListener('click', restartExam);
    actions.appendChild(retry);

    if (result.login_required) {
      // Anonymous user — push them toward signing in to save scores
      var signIn = document.createElement('a');
      signIn.href = '/auth/login?next=/practice-exam/';
      signIn.className = 'btn btn-outline';
      signIn.textContent = 'Sign in to save your score';
      actions.appendChild(signIn);
    } else if (isAuthenticated()) {
      // Logged in — link to history
      var history = document.createElement('a');
      history.href = '/practice-exam/history';
      history.className = 'btn btn-outline';
      history.textContent = 'View past attempts';
      actions.appendChild(history);
    }
  }

  // ════════════════════════════════════════════════════════════════════════
  //  RESTART
  // ════════════════════════════════════════════════════════════════════════

  function restartExam() {
    // Reset all state and return to start screen
    state.questions   = [];
    state.answers     = {};
    state.flagged     = {};
    state.currentIdx  = 0;
    state.finished    = false;
    state.reviewItems = [];
    state.startedAt   = null;
    if (state.timerId) clearInterval(state.timerId);

    // Reset start-screen button label
    var startBtn = document.querySelector('#screen-start .btn-accent');
    if (startBtn) {
      startBtn.disabled = false;
      startBtn.textContent = 'Begin exam';
    }

    // Reset timer display
    var timerEl = $('timer-display');
    if (timerEl) {
      timerEl.textContent = formatTime(state.durationSecs);
      timerEl.classList.remove('warn');
    }

    show('screen-start');
  }

  // ════════════════════════════════════════════════════════════════════════
  //  EXPOSE FOR INLINE onclick="" IN TEMPLATE
  // ════════════════════════════════════════════════════════════════════════
  //
  // Your practice_exam.html uses inline onclick handlers for the start-screen
  // buttons (selectSet, startExam, toggleFlag, prevQ, nextQ, restartExam).
  // We expose these on window so those calls resolve.

  window.selectSet    = selectSet;
  window.startExam    = startExam;
  window.toggleFlag   = toggleFlag;
  window.prevQ        = prevQ;
  window.nextQ        = nextQ;
  window.restartExam  = restartExam;

  // ════════════════════════════════════════════════════════════════════════
  //  INIT
  // ════════════════════════════════════════════════════════════════════════

  function init() {
    // Render domain card preview on start screen (static fallback meta)
    renderDomainCardsStart();

    // Default selection
    selectSet(1);

    // Initialize timer label so it doesn't say "90:00" before fetch finishes
    var timerEl = $('timer-display');
    if (timerEl) timerEl.textContent = formatTime(DEFAULT_DURATION_SECS);

    // Initialize counters
    updateAnsweredCount();
    updateProgress();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();