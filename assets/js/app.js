// Phoenix JS comes from the Hex deps (resolved via tsconfig.json paths),
// UI packages (topbar, ...) are installed from npm with bun.
import "phoenix_html"
import {Socket} from "phoenix"
import {LiveSocket} from "phoenix_live_view"
import topbar from "topbar"

const Hooks = {}

// Copies `data-copy` to the clipboard and briefly flips the label.
Hooks.CopyToClipboard = {
  mounted() {
    this.el.addEventListener("click", () => {
      const text = this.el.dataset.copy
      if (!text || !navigator.clipboard) return
      navigator.clipboard.writeText(text).then(() => {
        this.el.dataset.copied = "true"
        setTimeout(() => delete this.el.dataset.copied, 1200)
      })
    })
  },
}

// Renders an ISO-8601 timestamp in the browser's locale and timezone.
Hooks.LocalTime = {
  mounted() { this.render() },
  updated() { this.render() },
  render() {
    const iso = this.el.dataset.iso
    if (!iso) return
    const d = new Date(iso)
    if (isNaN(d)) return
    this.el.textContent = d.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit",
    })
    this.el.title = d.toISOString()
  },
}

// "/" focuses the search box, like most dashboards.
window.addEventListener("keydown", e => {
  if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return
  const t = e.target
  if (t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t.isContentEditable) return
  const search = document.querySelector("[data-search-input]")
  if (search) { e.preventDefault(); search.focus(); search.select() }
})

const csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content")
const liveSocket = new LiveSocket("/live", Socket, {
  longPollFallbackMs: 2500,
  params: {_csrf_token: csrfToken},
  hooks: Hooks,
})

// Show progress bar on live navigation and form submits (mudrock primary)
topbar.config({barColors: {0: "#6e4a7e"}, shadowColor: "rgba(0, 0, 0, .2)"})
window.addEventListener("phx:page-loading-start", _info => topbar.show(300))
window.addEventListener("phx:page-loading-stop", _info => topbar.hide())

liveSocket.connect()

// expose liveSocket on window for web console debug logs and latency simulation:
// >> liveSocket.enableDebug()
window.liveSocket = liveSocket
