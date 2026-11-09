import {createRoot} from "react-dom/client";
import {useEffect, useRef, useState} from "react";
import {z} from "zod";

import {api, type ArtifactVersion} from "@/api/client";
import {documentBaseUrl} from "@/review/content-host-url";
import {frameMessageSchema, reviewProtocolVersion, type ReviewInit} from "@/review-frame/protocol";

import "./style.css";

type EmbedLoad = {
  readonly artifactId: string;
  readonly artifactName: string;
  readonly entryPath: string;
  readonly html: string;
  readonly mode: "view" | "respond";
  readonly parentOrigin: string | null;
  readonly projectId: string;
  readonly publicView: boolean;
  readonly previewBaseUrl: string | null;
  readonly responseBinding: string | null;
  readonly version: ArtifactVersion;
};

function EmbedApp(): React.ReactNode {
  const frame = useRef<HTMLIFrameElement | null>(null);
  const [loaded, setLoaded] = useState<EmbedLoad | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [frameReady, setFrameReady] = useState(false);
  const query = new URLSearchParams(window.location.search);
  const artifactId = decodeURIComponent(window.location.pathname.split("/").at(-1) ?? "");
  const path = query.get("path") ?? "";
  const versionId = query.get("version") ?? undefined;
  const requestedMode = query.get("mode") === "respond" ? "respond" : "view";
  const questionId = query.get("question");
  const parentOrigin = document.querySelector<HTMLMetaElement>('meta[name="as-embed-parent"]')?.content ?? null;

  useEffect(() => {
    let current = true;
    void (async () => {
      try {
        const bootstrap = await api.embedBootstrap(artifactId, path, versionId);
        const mode = requestedMode === "respond" && bootstrap.canRespond ? "respond" : "view";
        const version = bootstrap.version;
        const [html, lease] = await Promise.all([
          api.versionFile(bootstrap.projectId, artifactId, version.version.id, path),
          api.previewLease(bootstrap.projectId, artifactId, version.version.id),
        ]);
        if (lease.versionId !== version.version.id) throw new Error("The preview lease resolved a different version.");
        if (current) setLoaded({
          artifactId, artifactName: bootstrap.artifact.name, entryPath: path, html,
          mode, parentOrigin, projectId: bootstrap.projectId, publicView: false,
          previewBaseUrl: lease.baseUrl,
          responseBinding: mode === "respond" ? questionId : null, version,
        });
      } catch {
        try {
          const publicBootstrap = await api.publicEmbedBootstrap(artifactId, path, versionId);
          if (current) setLoaded({
            artifactId, artifactName: publicBootstrap.artifact.name, entryPath: path,
            html: "", mode: "view", parentOrigin, projectId: publicBootstrap.projectId,
            publicView: true, responseBinding: null, version: publicBootstrap.version,
            previewBaseUrl: null,
          });
        } catch {
          if (current) {
            setMessage("Sign in to view this artifact.");
            postParent(parentOrigin, {type: "as-auth-required", v: 1});
          }
        }
      }
    })();
    return () => { current = false; };
  }, [artifactId, parentOrigin, path, questionId, requestedMode, versionId]);

  useEffect(() => {
    const onPopupMessage = (event: MessageEvent<unknown>): void => {
      const parsed = z.object({type: z.literal("as-embed-signed-in"), v: z.literal(1)}).safeParse(event.data);
      if (event.origin !== window.location.origin || !parsed.success) return;
      window.location.reload();
    };
    window.addEventListener("message", onPopupMessage);
    return () => window.removeEventListener("message", onPopupMessage);
  }, []);

  useEffect(() => {
    if (loaded !== null && !loaded.publicView && frameReady) {
      const target = frame.current?.contentWindow;
      if (target !== null && target !== undefined) {
        const init: ReviewInit = {
          annotations: [],
          baseHref: documentBaseUrl(loaded.previewBaseUrl ?? loaded.version.links.version, loaded.entryPath),
          entryPath: loaded.entryPath,
          html: addFragmentScript(loaded.html, window.location.hash),
          isLight: true,
          readOnly: true,
          themeTokens: {},
          type: "as-review-init",
          v: reviewProtocolVersion,
        };
        target.postMessage(init, window.location.origin);
      }
    }
  }, [frameReady, loaded]);

  useEffect(() => {
    if (loaded === null || loaded.publicView) return undefined;
    const onFrameMessage = (event: MessageEvent<unknown>): void => {
      if (event.source !== frame.current?.contentWindow || event.origin !== window.location.origin) return;
      const parsed = frameMessageSchema.safeParse(event.data);
      if (!parsed.success) return;
      const bridge = parsed.data;
      if (bridge.type === "as-review-ready") {
        setFrameReady(true);
        return;
      }
      if (bridge.type === "as-artifact-resize") {
        postParent(loaded.parentOrigin, {height: bridge.height, type: "as-embed-resize", v: 1});
        return;
      }
      if (bridge.type !== "as-artifact-bridge-request") return;
      void (async () => {
        let result: unknown;
        let error: string | undefined;
        if (bridge.operation !== "respond") {
          error = "This embed only supports artifact responses.";
        } else if (loaded.mode === "view" || loaded.publicView) {
          error = "Responses are disabled in view mode.";
        } else {
          try {
            const response = loaded.responseBinding === null
              ? await api.createArtifactResponse(loaded.projectId, loaded.artifactId, loaded.version.version.id, bridge.questionId, bridge.choice ?? null, bridge.data ?? null)
              : await api.createEmbeddedArtifactResponse(loaded.projectId, loaded.artifactId, loaded.version.version.id, bridge.questionId, bridge.choice ?? null, bridge.data ?? null, loaded.responseBinding);
            result = response;
            postParent(loaded.parentOrigin, {
              questionId: response.questionId,
              responseId: response.id,
              type: "as-response-recorded",
              v: 1,
            });
          } catch (cause) {
            error = cause instanceof Error ? cause.message : "The response could not be recorded.";
          }
        }
        frame.current?.contentWindow?.postMessage({
          ...(error === undefined ? {result} : {error}),
          id: bridge.id,
          ok: error === undefined,
          type: "as-artifact-bridge-response",
          v: reviewProtocolVersion,
        }, window.location.origin);
      })();
    };
    window.addEventListener("message", onFrameMessage);
    return () => { window.removeEventListener("message", onFrameMessage); };
  }, [loaded]);

  if (message !== null) {
    return <main className="as-embed-auth"><p>{message}</p><button onClick={() => {
      const popup = window.open("/auth/login?returnTo=" + encodeURIComponent("/embed/signed-in"), "artifact-server-login", "popup,width=540,height=720");
      if (popup === null) setMessage("Your browser blocked the sign-in popup. Allow popups for this site, then try again.");
    }} type="button">Sign in to view</button></main>;
  }
  if (loaded === null) return <main className="as-embed-loading" aria-busy="true">Loading artifact…</main>;
  if (loaded.publicView) {
    const publicUrl = new URL(loaded.version.links.version);
    publicUrl.pathname = "/" + loaded.entryPath.split("/").map(encodeURIComponent).join("/");
    publicUrl.hash = window.location.hash;
    return <iframe className="as-embed-public" ref={frame} src={publicUrl.toString()} title={loaded.artifactName} />;
  }
  return <iframe className="as-embed-frame" ref={frame} src="/review-frame?embed=1" title={loaded.artifactName} />;
}

function addFragmentScript(html: string, fragment: string): string {
  if (fragment === "") return html;
  const encoded = JSON.stringify(fragment).replaceAll("<", "\\u003c");
  const script = "<script>location.hash=" + encoded + "</script>";
  return /<\/body\s*>/iu.test(html)
    ? html.replace(/<\/body\s*>/iu, script + "</body>")
    : html + script;
}

type ParentEmbedMessage =
  | {readonly type: "as-auth-required"; readonly v: 1}
  | {readonly height: number; readonly type: "as-embed-resize"; readonly v: 1}
  | {readonly questionId: string; readonly responseId: string; readonly type: "as-response-recorded"; readonly v: 1};

function postParent(
  origin: string | null,
  message: ParentEmbedMessage,
): void {
  if (origin === null || !/^https?:\/\//u.test(origin)) return;
  window.parent.postMessage(
    message.type === "as-embed-resize"
      ? {...message, height: Math.min(10_000, Math.max(0, Math.ceil(message.height)))}
      : message,
    origin,
  );
}

const root = document.getElementById("embed-root");
if (root === null) throw new Error("The embed root is missing.");
createRoot(root).render(<EmbedApp />);
