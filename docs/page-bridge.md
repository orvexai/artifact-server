# Page bridge

The page bridge lets a page use a small set of Artifact Server operations while a signed-in user has that artifact open in exact Review. It is available as `window.artifactServer` inside the reviewed page. Every call is made through Review; the page does not receive an API token.

The bridge is available only in authenticated exact Review. Public links run no bridge. An embedded review allows only `respond()`; its other bridge operations are refused.

## Per-artifact state

These calls read or change state shared by the artifact and its agents. They do not show a consent prompt:

- `state.list()` returns the artifact's state entries.
- `state.get(key)` reads one entry.
- `state.set(key, value)` writes a JSON value.
- `state.delete(key)` deletes an entry.

A key contains 1–200 non-control characters. A value may use up to 64 KiB of UTF-8 JSON; an artifact may have at most 128 keys and 1 MiB of state in total. Agents read state with `artifact_state_list` and `artifact_state_get`.

## Comment threads

`comments.create(body, {path})` asks the viewer to confirm before posting as them. The body must contain 1–8,192 characters. The optional path must name a file in the exact version being reviewed. The options object accepts only `path`; an unsupported option is dropped by validation and the page call times out.

For a body of 500 characters or fewer, the prompt shows the full body. For a longer body, it shows the first 500 characters, an ellipsis, and a note with the total character count. Accepting resolves to `{threadId}`. The thread belongs to the reviewed version; agents can read it with `comment_list` or `comment_get`. Review uses the idempotency key `page-<request id>` for the post.

Dismissing the prompt rejects with `The viewer declined the comment.`. A path or comment rejected by the API also rejects the page call with the returned error.

## Responses

`respond({questionId, choice, data})` asks the viewer before submitting a response. The question ID must contain 1–200 characters, the optional choice may contain up to 200 characters, and optional data must be JSON of at most 16 KiB. The prompt shows the question and up to 500 characters of the serialized choice and data. Dismissing it rejects with `The viewer declined the response.`.

## Shared request limits and errors

A page bridge request message is limited to 70 KiB. Each open preview allows 30 requests per rolling 60 seconds across state, comments, and responses. The 31st request is rejected with `Artifact bridge request limit exceeded.` and does not show a prompt. Each page call must receive a response within 15 seconds or rejects with `Artifact bridge timed out.`. Invalid or unknown bridge messages are dropped without a reply, so their page call times out.

## Example

Add a button to a page to send its triage note. The prompt gives the viewer a chance to review and approve the text before it is posted.

```html
<button id="send-triage">Send my triage to the team</button>
<script>
  document.querySelector("#send-triage").addEventListener("click", async () => {
    try {
      const {threadId} = await window.artifactServer.comments.create(
        "Triage: ship the release notes",
        {path: "index.html"},
      );
      document.body.dataset.triageThread = threadId;
    } catch (error) {
      document.body.dataset.triageError = error.message;
    }
  });
</script>
```
