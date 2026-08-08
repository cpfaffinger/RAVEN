document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy-target]");
  if (!button) return;
  const target = document.getElementById(button.dataset.copyTarget);
  const result = button.parentElement.querySelector(".copy-result");
  if (!target) return;
  try {
    await navigator.clipboard.writeText(target.value);
    button.textContent = "Kopiert";
    if (result) result.textContent = "Der vollständige Befehl liegt in der Zwischenablage.";
  } catch (_error) {
    target.focus();
    target.select();
    if (result) result.textContent = "Bitte den markierten Befehl manuell kopieren.";
  }
});
