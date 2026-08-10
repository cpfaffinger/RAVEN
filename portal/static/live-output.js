// Follows a running job by polling its output endpoint, so a long replication
// can be watched without reloading the page and losing the scroll position.
document.addEventListener("DOMContentLoaded", () => {
  const view = document.querySelector("[data-live-source]");
  if (!view) return;
  const source = view.dataset.liveSource;
  const output = view.querySelector(".live-output");
  const badge = view.querySelector(".live-status");
  const note = view.querySelector(".live-note");
  let timer = null;

  const atBottom = () =>
    output.scrollHeight - output.scrollTop - output.clientHeight < 40;

  const poll = async () => {
    try {
      const response = await fetch(source, { cache: "no-store" });
      if (!response.ok) return stop("Aktualisierung fehlgeschlagen");
      const data = await response.json();
      const stick = atBottom();
      if (data.output && data.output !== output.textContent) {
        output.textContent = data.output;
        if (stick) output.scrollTop = output.scrollHeight;
      }
      if (badge) {
        badge.textContent = data.status.toUpperCase();
        badge.className = "status live-status " + data.status;
      }
      if (!data.running) {
        stop("Lauf beendet, Seite neu laden für alle Kennzahlen");
        return;
      }
      if (note) note.textContent = "Live · aktualisiert alle 3 Sekunden";
    } catch (_error) {
      stop("Verbindung zum Portal unterbrochen");
    }
  };

  const stop = (message) => {
    if (timer) window.clearInterval(timer);
    timer = null;
    if (note) note.textContent = message;
  };

  poll();
  timer = window.setInterval(poll, 3000);
});
