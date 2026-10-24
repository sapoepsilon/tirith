"""A tiny OpenAI-compatible server (stdlib only) for testing llm.py: /v1/models + /v1/chat/completions."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeOpenAI:
    def __init__(self, api_key: str = "sk-fake-123", model: str = "deepseek-r1-fake", mode: str = "reasoning_field",
                 content: str = '{"summary": "s", "root_cause": "r", "exploitability": "e", "fix_plan": "f"}',
                 reasoning: str = "First I trace the input. Then the sink. ", reject_response_format: bool = False):
        self.api_key, self.model, self.mode = api_key, model, mode
        self.content, self.reasoning = content, reasoning
        self.reject_response_format = reject_response_format
        self.requests: list[dict] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _auth(self) -> bool:
                if self.headers.get("Authorization") != f"Bearer {outer.api_key}":
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"Unauthorized"}')
                    return False
                return True

            def do_GET(self):
                if not self._auth():
                    return
                if self.path.rstrip("/") == "/v1/models":
                    body = json.dumps({"object": "list", "data": [{"id": outer.model, "object": "model"}, {"id": "other"}]}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                if not self._auth():
                    return
                n = int(self.headers.get("Content-Length", "0"))
                req = json.loads(self.rfile.read(n) or b"{}")
                outer.requests.append(req)
                if outer.reject_response_format and "response_format" in req:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"response_format unsupported"}')
                    return
                content, reasoning = outer.content, outer.reasoning
                if outer.mode == "think_tags":
                    content, reasoning = f"<think>{reasoning}</think>\n{content}", ""
                if req.get("stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    chunks = [{"reasoning_content": reasoning[i:i + 7]} for i in range(0, len(reasoning), 7)]
                    chunks += [{"content": content[i:i + 9]} for i in range(0, len(content), 9)]
                    for c in chunks:
                        d = {"id": "x", "model": outer.model, "choices": [{"index": 0, "delta": c, "finish_reason": None}]}
                        self.wfile.write(f"data: {json.dumps(d)}\n\n".encode())
                    end = {"id": "x", "model": outer.model, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": 5, "completion_tokens": 9}}
                    self.wfile.write(f"data: {json.dumps(end)}\n\ndata: [DONE]\n\n".encode())
                else:
                    msg = {"role": "assistant", "content": content}
                    if reasoning:
                        msg["reasoning_content"] = reasoning
                    body = json.dumps({"id": "x", "model": outer.model, "choices": [{"index": 0, "message": msg, "finish_reason": "stop"}],
                                       "usage": {"total_tokens": 3}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.server.shutdown()
        self.server.server_close()
