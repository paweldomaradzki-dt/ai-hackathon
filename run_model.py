import hashlib
import hmac
import json
import os
import urllib.parse

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


async def search_similar_issues(owner: str, repo: str, title: str, body: str, current_number: int) -> list:
    body_words = " ".join((body or "").split()[:100])
    query = f"{title} {body_words}".strip()
    q = urllib.parse.quote(f"{query} repo:{owner}/{repo} is:issue")
    url = f"https://api.github.com/search/issues?q={q}&per_page=5"

    async with httpx.AsyncClient() as http:
        resp = await http.get(
            url,
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
            },
        )

    if resp.status_code != 200:
        print(f"GitHub search failed: {resp.status_code} {resp.text}")
        return []

    items = resp.json().get("items", [])
    return [i for i in items if i["number"] != current_number]


async def post_comment(comments_url: str, comment: str) -> None:
    async with httpx.AsyncClient() as http:
        resp = await http.post(
            comments_url,
            json={"body": comment},
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
            },
        )
    print(f"Posted comment to GitHub: {resp.status_code}")


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
    action = payload.get("action")
    print(f"\n--- GitHub Event: {x_github_event} / action: {action} ---")
    print(json.dumps(payload, indent=2))

    if x_github_event != "issues" or action != "opened":
        return {"ok": True}

    issue = payload.get("issue", {})
    issue_title = issue.get("title") or ""
    issue_body = issue.get("body") or ""
    issue_number = issue.get("number")
    comments_url = issue.get("comments_url", "")
    repo = payload.get("repository", {})
    repo_owner = repo.get("owner", {}).get("login", "")
    repo_name = repo.get("name", "")

    if github_token and repo_owner and repo_name:
        similar = await search_similar_issues(repo_owner, repo_name, issue_title, issue_body, issue_number)
        if similar:
            refs = ", ".join(f"#{i['number']} [{i['title']}]({i['html_url']})" for i in similar)
            comment = f"Similar issues already exist — you may find answers there:\n\n{refs}"
            print(f"\n--- Similar issues found, skipping Claude ---\n{refs}")
            if comments_url:
                await post_comment(comments_url, comment)
            return {"ok": True}

    print(f"\n--- No similar issues found, sending to Claude ---\n{issue_body!r}\n---")

    message = client.messages.create(
        model=model,
        system=system_prompt + " You are analyzing issues for a Dynatrace repository. Always focus your analysis on Dynatrace products, observability, monitoring, and APM topics. If an issue is unrelated to Dynatrace, briefly note that and suggest the appropriate channel.",
        messages=[
            {"role": "user", "content": issue_body or "(empty issue body)"},
        ],
        max_tokens=1024,
    )

    text = next((b.text for b in message.content if b.type == "text"), "")
    print(f"\n--- Claude response ---\n{text}")

    if comments_url and github_token:
        await post_comment(comments_url, text)

    return {"ok": True}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)
