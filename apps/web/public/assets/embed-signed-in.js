if (window.opener) {
  window.opener.postMessage({type: "as-embed-signed-in", v: 1}, window.location.origin);
}
window.close();
