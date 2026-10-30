// Draws the Chart.js charts. Colours match the severity badges in style.css.
(function () {
  var COLORS = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#facc15", LOW: "#22c55e" };
  if (typeof Chart === "undefined") { return; }   // CDN unreachable: page still works without charts
  Chart.defaults.color = "#8d99c4";

  function doughnut(canvas, counts) {
    var labels = Object.keys(COLORS);
    new Chart(canvas, {
      type: "doughnut",
      data: { labels: labels, datasets: [{ data: labels.map(function (k) { return counts[k] || 0; }),
              backgroundColor: labels.map(function (k) { return COLORS[k]; }), borderWidth: 0 }] },
      options: { maintainAspectRatio: false, cutout: "62%", plugins: { legend: { position: "bottom" } } }
    });
  }

  var sev = document.getElementById("sevChart");
  if (sev) {                                       // dashboard page
    fetch("/api/stats").then(function (r) { return r.json(); }).then(function (s) {
      doughnut(sev, s.severity);
      new Chart(document.getElementById("trendChart"), {
        type: "line",
        data: { labels: s.trend.map(function (t) { return "#" + t.id; }),
                datasets: [{ label: "Risk score", data: s.trend.map(function (t) { return t.risk_score; }),
                             borderColor: "#22d3ee", backgroundColor: "rgba(34,211,238,.15)", fill: true, tension: .3 }] },
        options: { maintainAspectRatio: false, scales: { y: { min: 0, max: 100 } }, plugins: { legend: { display: false } } }
      });
    }).catch(function () {});
  }

  var res = document.getElementById("resChart");  // results page
  if (res) { doughnut(res, JSON.parse(res.dataset.counts)); }
})();
