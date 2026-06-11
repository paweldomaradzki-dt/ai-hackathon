import hashlib
import hmac
import json
import os

import httpx
import uvicorn
from anthropic import Anthropic, AnthropicFoundry
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request

load_dotenv()

PORT = int(os.environ.get("PORT", 3000))
SECRET = os.environ.get("WEBHOOK_SECRET", "")
endpoint = os.environ.get("CLAUDE_ENDPOINT", "")
model = os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5")
api_key = os.environ.get("ANTHROPIC_API_KEY", "")
github_token = os.environ.get("GITHUB_TOKEN", "")
system_prompt = os.environ.get(
    "CLAUDE_SYSTEM_PROMPT",
    "You are an assistant that analyzes GitHub webhook events.",
)

client = AnthropicFoundry(api_key=api_key, base_url=endpoint) if endpoint else Anthropic(api_key=api_key)

app = FastAPI()


def verify_signature(body: bytes, sig_header: str) -> bool:
    expected = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header)


@app.post("/webhook")
async def webhook(
    request: Request,
    x_github_event: str = Header(default="unknown"),
    x_hub_signature_256: str = Header(default=""),
):
    body = await request.body()

    print(f"DEBUG: received {len(body)} bytes, body={body[:200]!r}, event={x_github_event!r}")

    if not body.strip():
        raise HTTPException(status_code=400, detail="Empty body")

    if SECRET:
        if not x_hub_signature_256 or not verify_signature(body, x_hub_signature_256):
            print("Invalid signature — request rejected")
            raise HTTPException(status_code=401, detail="Unauthorized")

    payload = json.loads(body)
    print(f"\n--- GitHub Event: {x_github_event} / action: {payload.get('action')} ---")
    print(json.dumps(payload, indent=2))

    issue = payload.get("issue", {})
    content = issue.get("body") or ""
    comments_url = issue.get("comments_url", "")
    print(f"\n--- Sending to Claude ---\n{content!r}\n---")

    message = client.messages.create(
        model=model,
        system=system_prompt,
        messages=[
            {"role": "user", "content": content or "(empty issue body)"},
        ],
        max_tokens=1024,
    )

    text = next((b.text for b in message.content if b.type == "text"), "")
    print(f"\n--- Claude response ---\n{text}")

    if comments_url and github_token:
        async with httpx.AsyncClient() as http:
            resp = await http.post(
                comments_url,
                json={"body": text},
                headers={
                    "Authorization": f"Bearer {github_token}",
                    "Accept": "application/vnd.github+json",
                },
            )
        print(f"Posted comment to GitHub: {resp.status_code}")

    return {"ok": True}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)
