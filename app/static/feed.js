/* The change feed page: arrival animation, live polling, kind filter, copy.
   Everything here is an enhancement. Without JS the server-rendered ten rows stand. */
(function () {
  var tape = document.getElementById('tape');
  if (!tape) return;
  var list = document.getElementById('tape-rows');
  var checked = document.getElementById('tape-checked');
  var watch = document.getElementById('tape-watch');
  var strip = document.querySelector('.fe-strip div:last-child b');
  var endpoint = tape.dataset.feed || '/feed.json';
  var newest = parseInt(tape.dataset.newest || '0', 10);
  var kind = tape.dataset.kind || '';
  var timer = null;
  var slow = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function ago(ts) {
    var t = Date.parse(ts);
    if (isNaN(t)) return '';
    var s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 90) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 172800) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }

  function relabel(root) {
    (root || document).querySelectorAll('.r-when[data-ts]').forEach(function (el) {
      var a = ago(el.dataset.ts);
      if (a) el.textContent = a;
    });
  }

  function stagger(root) {
    var rows = (root || list).querySelectorAll('.tape-row');
    rows.forEach(function (row, i) {
      row.classList.remove('in');
      if (slow) { row.classList.add('in'); return; }
      setTimeout(function () { row.classList.add('in'); }, 40 * i);
    });
  }

  function markArrivals(root) {
    root.querySelectorAll('.tape-row').forEach(function (row) {
      row.classList.add('in', 'arrived');
      setTimeout(function () { row.classList.remove('arrived'); }, 2200);
    });
  }

  function setState(newRows) {
    var stale = newest && strip ? false : true;
    if (watch) watch.textContent = 'watching';
    if (strip && newest) {
      var first = list.querySelector('.r-when[data-ts]');
      if (first) strip.textContent = ago(first.dataset.ts);
    }
    if (checked) checked.textContent = 'checked ' + new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (newRows) {
      tape.classList.add('flash');
      setTimeout(function () { tape.classList.remove('flash'); }, 700);
    }
  }

  function trim() {
    var rows = list.querySelectorAll('.tape-row');
    for (var i = 10; i < rows.length; i++) rows[i].remove();
    list.querySelectorAll('.tape-run').forEach(function (h) {
      var n = h.nextElementSibling;
      if (!n || !n.classList.contains('tape-row')) h.remove();
    });
  }

  function poll() {
    if (document.hidden || !newest) return;
    var url = endpoint + '?after_id=' + newest + (kind ? '&kind=' + kind : '');
    fetch(url, { cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (data) {
        var fresh = (data.changes || []).filter(function (c) { return c.id > newest; });
        if (fresh.length) {
          var html = fresh.map(function (c) { return c.html; }).join('');
          var box = document.createElement('div');
          box.innerHTML = html;
          markArrivals(box);
          var first = box.firstElementChild;
          var top = list.firstElementChild;
          if (first && first.classList.contains('tape-run') && top &&
              top.classList.contains('tape-run') &&
              first.textContent.trim() === top.textContent.trim()) {
            first.remove();
          }
          var anchor = list.firstChild;
          while (box.firstChild) list.insertBefore(box.firstChild, anchor);
          trim();
          newest = data.newest_id || fresh[0].id;
          tape.dataset.newest = newest;
          setState(true);
        } else {
          setState(false);
        }
        relabel(list);
      })
      .catch(function () {
        if (watch) watch.textContent = 'reconnecting';
        if (checked) checked.textContent = 'feed unreachable';
      });
  }

  function load(k) {
    fetch(endpoint + (k ? '?kind=' + k : ''), { cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (data) {
        kind = k;
        tape.dataset.kind = k;
        newest = data.newest_id || 0;
        tape.dataset.newest = newest;
        list.innerHTML = (data.changes || []).map(function (c) { return c.html; }).join('') ||
          '<li class="tape-empty">No changes recorded for that filter yet.</li>';
        stagger(null);
        relabel(list);
        setState(false);
      })
      .catch(function () {});
  }

  document.querySelectorAll('.tape-filters .kfilter').forEach(function (a) {
    a.addEventListener('click', function (ev) {
      ev.preventDefault();
      var k = a.dataset.kind || '';
      document.querySelectorAll('.tape-filters .kfilter').forEach(function (x) {
        x.classList.toggle('on', x === a);
      });
      history.replaceState(null, '', a.getAttribute('href'));
      load(k);
    });
  });

  var replay = document.getElementById('tape-replay');
  if (replay) replay.addEventListener('click', function () { stagger(null); });

  var copy = document.querySelector('.snippet .copy');
  if (copy) copy.addEventListener('click', function () {
    var pre = copy.closest('.snippet').querySelector('pre');
    if (!pre) return;
    navigator.clipboard.writeText(pre.innerText).then(function () {
      copy.textContent = 'copied';
      setTimeout(function () { copy.textContent = 'copy'; }, 1600);
    }, function () { copy.textContent = 'select and copy'; });
  });

  setState(false);
  stagger(null);
  relabel(list);
  timer = setInterval(poll, 20000);
  setInterval(function () { relabel(list); }, 30000);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) poll(); });
  window.addEventListener('beforeunload', function () { clearInterval(timer); });
})();
