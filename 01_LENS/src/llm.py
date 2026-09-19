from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional

import requests

from .parsing import is_refusal, is_provider_block
from .easy_api_client import EasyAPIClient


try:
    import tiktoken
    _ENCODER = tiktoken.get_encoding("cl100k_base")
except Exception:
    _ENCODER = None


def count_tokens(text: str) -> int:
    if not text:
        return 0
    if _ENCODER is None:
        return max(1, len(text) // 4)
    return len(_ENCODER.encode(text, disallowed_special=()))


class LLMRunner:
    def __init__(self, service_name: str, max_retries: int = 5, retry_sleep_s: float = 2.0,
                 search_service_name: Optional[str] = None,
                 websearch_max_retries: Optional[int] = None):
        self.service_name = service_name
        self.client = EasyAPIClient()
        service_config = self.client.config.get(service_name, {})
        # Retrieval may use a different service from prompt induction and analysis.
        self.search_service_name = (
            search_service_name
            or service_config.get("search_service")
            or service_name
        )
        self.max_retries = max_retries
        self.retry_sleep_s = retry_sleep_s
        # Search retries are configurable independently of plain generation.
        self.websearch_max_retries = websearch_max_retries
        self.last_error: Optional[str] = None
        self._stats_lock = threading.Lock()
        self._stats: Dict = {
            "calls": 0,
            "successes": 0,
            "failures": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "total_latency_s": 0.0,
        }

    def generate(self, prompt: str, retry_on_refusal: bool = False, tag: Optional[str] = None) -> Optional[str]:
        last_error = None
        prompt_tokens = count_tokens(prompt)
        started = time.time()
        for attempt in range(self.max_retries):
            try:
                service_cfg = self.client.config.get(self.service_name, {})
                provider = str(service_cfg.get("type", "openai_compatible")).lower()
                if provider == "openai":
                    text = self._openai_generate(prompt)
                    result = {"success": bool(text and text.strip()), "text": text or ""}
                elif provider == "anthropic":
                    text = self._anthropic_generate(prompt)
                    result = {"success": bool(text and text.strip()), "text": text or ""}
                elif provider == "gemini":
                    text = self._gemini_native_generate(prompt)
                    result = {"success": bool(text and text.strip()), "text": text or ""}
                else:
                    result = self.client.generate_text(prompt, service_name=self.service_name)
                if result.get("success") and result.get("text", "").strip():
                    text = result["text"].strip()
                    if is_provider_block(text):
                        # Treat provider block messages as retryable failures.
                        last_error = f"provider_block: {text[:80]}"
                    elif is_refusal(text):
                        # Do not persist a refusal as an induced instruction.
                        last_error = f"refusal: {text[:120]}"
                    else:
                        self.last_error = None
                        self._record(prompt_tokens, count_tokens(text), time.time() - started, success=True)
                        return text
                else:
                    last_error = result.get("text", "empty response")
            except Exception as exc:
                last_error = str(exc)

            if attempt < self.max_retries - 1:
                time.sleep(self.retry_sleep_s)

        self.last_error = last_error
        self._record(prompt_tokens, 0, time.time() - started, success=False)
        print(f"  [LLM ERROR] {last_error}")
        return None

    _GEMINI_SAFETY_CATEGORIES = [
        "HARM_CATEGORY_HARASSMENT",
        "HARM_CATEGORY_HATE_SPEECH",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "HARM_CATEGORY_DANGEROUS_CONTENT",
        "HARM_CATEGORY_CIVIC_INTEGRITY",
    ]

    def _gemini_generation_config(self, cfg: Dict) -> Dict:
        """Build generationConfig without imposing an unspecified token cap."""
        gen: Dict = {}
        if cfg.get("temperature") is not None:
            gen["temperature"] = float(cfg["temperature"])
        cap = cfg.get("max_output_tokens") or cfg.get("max_tokens")
        if cap:
            gen["maxOutputTokens"] = int(cap)
        return gen

    def _gemini_native_generate(self, prompt: str) -> Optional[str]:
        cfg = self.client.config.get(self.service_name, {})
        base = (
            cfg.get("base_url")
            or cfg.get("native_base_url")
            or cfg.get("gemini_base_url")
            or "https://generativelanguage.googleapis.com/v1beta"
        ).rstrip("/")
        key = (
            cfg.get("native_key")
            or cfg.get("gemini_api_key")
            or (cfg.get("keys") or [None])[0]
        )
        model = cfg.get("default_model")
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": self._gemini_generation_config(cfg),
            "safetySettings": [
                {"category": c, "threshold": "BLOCK_NONE"} for c in self._GEMINI_SAFETY_CATEGORIES
            ],
        }
        response = requests.post(
            f"{base}/models/{model}:generateContent",
            headers={"x-goog-api-key": key, "Content-Type": "application/json"},
            json=payload,
            timeout=300,
        )
        if response.status_code != 200:
            raise RuntimeError(f"HTTP {response.status_code}: {response.text[:300]}")
        candidates = response.json().get("candidates") or []
        parts = ((candidates[0].get("content") if candidates else {}) or {}).get("parts") or []
        return "".join(p.get("text", "") for p in parts).strip()

    def _openai_generate(self, prompt: str) -> Optional[str]:
        cfg = self.client.config.get(self.service_name, {})
        key = self.client._get_available_key(self.service_name)
        model = cfg.get("default_model", "")
        if not key or not model:
            raise RuntimeError(f"missing OpenAI config for service={self.service_name}")
        result = self._post_openai_response(
            cfg, key, model, prompt, timeout_s=300, use_web_search=False
        )
        return result.get("text") if result else None

    def _anthropic_generate(self, prompt: str) -> Optional[str]:
        cfg = self.client.config.get(self.service_name, {})
        key = self.client._get_available_key(self.service_name)
        model = cfg.get("default_model", "")
        if not key or not model:
            raise RuntimeError(f"missing Anthropic config for service={self.service_name}")
        result = self._post_anthropic_message(
            cfg, key, model, prompt, timeout_s=300, use_web_search=False
        )
        return result.get("text") if result else None

    def _record(self, prompt_tokens: int, completion_tokens: int, latency_s: float, success: bool) -> None:
        with self._stats_lock:
            self._stats["calls"] += 1
            if success:
                self._stats["successes"] += 1
            else:
                self._stats["failures"] += 1
            self._stats["prompt_tokens"] += prompt_tokens
            self._stats["completion_tokens"] += completion_tokens
            self._stats["total_tokens"] += prompt_tokens + completion_tokens
            self._stats["total_latency_s"] += latency_s

    def get_stats(self) -> Dict:
        with self._stats_lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        with self._stats_lock:
            for k in self._stats:
                self._stats[k] = 0 if isinstance(self._stats[k], (int,)) else 0.0

    # ------------------------------------------------------------------
    # Web-search-enabled calls.
    # ------------------------------------------------------------------
    def generate_with_websearch(
        self,
        prompt: str,
        nudge: Optional[str] = None,
        timeout_s: int = 600,
        tag: Optional[str] = None,
    ) -> Optional[Dict]:
        """Call a web-search-capable generation endpoint.

        Returns a dict ``{"text", "search_calls", "usage", "elapsed_s"}`` on
        success, or ``None`` on failure. ``self._stats`` is updated like a
        regular ``generate()`` call.
        """
        search_service = self.search_service_name
        service_cfg = self.client.config.get(search_service, {})
        api_key = self.client._get_available_key(search_service)
        base_url = service_cfg.get("base_url", "").rstrip("/")
        model = service_cfg.get("default_model", "")
        if not api_key or not base_url or not model:
            print(f"  [LLM web_search ERROR] missing config for service={search_service}")
            return None

        combined = prompt
        if nudge:
            combined = prompt.rstrip() + "\n\n" + nudge.strip()
        fallback_prompt_tokens = count_tokens(combined)
        started = time.time()
        last_error: Optional[str] = None
        # Search backends can return transient tool-call or HTTP failures.
        ws_retries = self.websearch_max_retries or max(self.max_retries, 8)
        for attempt in range(ws_retries):
            try:
                backend = self._select_websearch_backend(service_cfg, model)
                if backend == "gemini":
                    result = self._post_gemini_google_search(
                        service_cfg, api_key, model, combined, timeout_s
                    )
                elif backend == "anthropic":
                    result = self._post_anthropic_message(
                        service_cfg, api_key, model, combined, timeout_s,
                        use_web_search=True,
                    )
                elif backend == "chat_tool":
                    result = self._post_chat_tool_websearch(
                        service_cfg, base_url, api_key, model, combined, timeout_s
                    )
                else:
                    result = self._post_openai_response(
                        service_cfg, api_key, model, combined, timeout_s,
                        use_web_search=True,
                    )
                if result and result.get("text"):
                    # Prefer the API-reported usage so we don't undercount the
                    # tool-call traffic web_search adds.
                    usage = result.get("usage") or {}
                    prompt_tokens = usage.get("input_tokens") or fallback_prompt_tokens
                    completion_tokens = (
                        usage.get("output_tokens")
                        if usage.get("output_tokens") is not None
                        else count_tokens(result["text"])
                    )
                    self._record(
                        prompt_tokens, completion_tokens,
                        time.time() - started, success=True,
                    )
                    return result
                last_error = "empty response"
            except Exception as exc:
                last_error = str(exc)
            if attempt < ws_retries - 1:
                time.sleep(min(self.retry_sleep_s * (1 + attempt), 12))

        self._record(fallback_prompt_tokens, 0, time.time() - started, success=False)
        print(f"  [LLM web_search ERROR] {last_error}")
        return None

    def _select_websearch_backend(self, service_cfg: Dict, model: str) -> str:
        """Pick how web-search-enabled calls are issued.

        Returns ``"responses"``, ``"anthropic"``, ``"gemini"``, or
        ``"chat_tool"`` according to the provider's native search API.
        """
        backend = (
            service_cfg.get("web_search_backend")
            or service_cfg.get("search_backend")
            or service_cfg.get("tool_backend")
        )
        if backend:
            b = str(backend).lower()
            if b in ("gemini", "google", "google_search"):
                return "gemini"
            if b in ("anthropic", "claude"):
                return "anthropic"
            if b in ("chat_tool", "chat", "glm", "openai_chat", "chat_web_search"):
                return "chat_tool"
            if b in ("responses", "openai", "openai_responses"):
                return "responses"
        provider = str(service_cfg.get("type", "")).lower()
        if provider == "anthropic" or model.startswith("claude-"):
            return "anthropic"
        if provider == "gemini" or model.startswith("gemini-"):
            return "gemini"
        if "glm" in model.lower():
            return "chat_tool"
        return "responses"

    def _post_openai_response(
        self,
        service_cfg: Dict,
        api_key: str,
        model: str,
        prompt: str,
        timeout_s: int,
        use_web_search: bool,
    ) -> Optional[Dict]:
        payload = {
            "model": model,
            "input": prompt,
        }
        if use_web_search:
            payload["tools"] = [{"type": "web_search"}]
            payload["include"] = ["web_search_call.action.sources"]
        max_output_tokens = service_cfg.get("max_output_tokens")
        if max_output_tokens:
            payload["max_output_tokens"] = int(max_output_tokens)

        base_url = (
            service_cfg.get("base_url") or "https://api.openai.com/v1"
        ).rstrip("/")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        t0 = time.time()
        response = requests.post(
            f"{base_url}/responses",
            headers=headers,
            json=payload,
            timeout=timeout_s,
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"HTTP {response.status_code}: {response.text[:500]}"
            )

        data = response.json()
        text_parts: List[str] = []
        search_calls: List[Dict] = []
        for item in data.get("output") or []:
            if item.get("type") == "web_search_call":
                search_calls.append(item)
            elif item.get("type") == "message":
                for c in item.get("content", []):
                    if c.get("type") == "output_text":
                        text_parts.append(c.get("text", ""))
                        citations = c.get("annotations") or []
                        if citations:
                            search_calls.extend(citations)

        return {
            "text": (data.get("output_text") or "\n".join(text_parts)).strip(),
            "search_calls": search_calls,
            "usage": data.get("usage") or {},
            "elapsed_s": time.time() - t0,
        }

    def _post_anthropic_message(
        self,
        service_cfg: Dict,
        api_key: str,
        model: str,
        prompt: str,
        timeout_s: int,
        use_web_search: bool,
    ) -> Optional[Dict]:
        max_tokens = int(
            service_cfg.get("max_output_tokens")
            or service_cfg.get("max_tokens")
            or 16384
        )
        messages: List[Dict] = [{"role": "user", "content": prompt}]
        payload: Dict = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if use_web_search:
            payload["tools"] = [
                {
                    "type": service_cfg.get(
                        "web_search_tool", "web_search_20250305"
                    ),
                    "name": "web_search",
                    "max_uses": int(
                        service_cfg.get("web_search_max_uses", 5)
                    ),
                }
            ]

        base_url = (
            service_cfg.get("base_url") or "https://api.anthropic.com/v1"
        ).rstrip("/")
        headers = {
            "x-api-key": api_key,
            "anthropic-version": service_cfg.get(
                "anthropic_version", "2023-06-01"
            ),
            "Content-Type": "application/json",
        }
        t0 = time.time()
        text_parts: List[str] = []
        search_calls: List[Dict] = []
        input_tokens = 0
        output_tokens = 0
        web_search_requests = 0
        max_pause_turns = int(service_cfg.get("max_pause_turns", 3))
        for pause_turn in range(max_pause_turns + 1):
            response = requests.post(
                f"{base_url}/messages",
                headers=headers,
                json=payload,
                timeout=timeout_s,
            )
            if response.status_code != 200:
                raise RuntimeError(
                    f"HTTP {response.status_code}: {response.text[:500]}"
                )

            data = response.json()
            content = data.get("content") or []
            for block in content:
                block_type = block.get("type")
                if block_type == "text":
                    text_parts.append(block.get("text", ""))
                    citations = block.get("citations") or []
                    if citations:
                        search_calls.extend(citations)
                elif block_type in {"server_tool_use", "web_search_tool_result"}:
                    search_calls.append(block)

            usage_raw = data.get("usage") or {}
            input_tokens += usage_raw.get("input_tokens") or 0
            output_tokens += usage_raw.get("output_tokens") or 0
            server_usage = usage_raw.get("server_tool_use") or {}
            web_search_requests += server_usage.get("web_search_requests") or 0

            if data.get("stop_reason") != "pause_turn":
                break
            if pause_turn == max_pause_turns:
                raise RuntimeError("Anthropic web search exceeded pause-turn limit")
            messages.append({"role": "assistant", "content": content})

        usage = {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "server_tool_use": {
                "web_search_requests": web_search_requests,
            },
        }
        return {
            "text": "\n".join(text_parts).strip(),
            "search_calls": search_calls,
            "usage": usage,
            "elapsed_s": time.time() - t0,
        }

    def _post_chat_tool_websearch(
        self,
        service_cfg: Dict,
        base_url: str,
        api_key: str,
        model: str,
        prompt: str,
        timeout_s: int,
    ) -> Optional[Dict]:
        """Use an OpenAI-compatible chat endpoint with native web search."""
        max_tokens = int(
            service_cfg.get("max_output_tokens")
            or service_cfg.get("max_tokens")
            or 16384
        )
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "tools": [
                {
                    "type": "web_search",
                    "web_search": {
                        "enable": True,
                        "search_engine": service_cfg.get(
                            "web_search_engine", "search_std"
                        ),
                        "search_result": True,
                    },
                }
            ],
            "temperature": 0,
            "max_tokens": max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        t0 = time.time()
        r = requests.post(
            f"{base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=timeout_s,
        )
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:500]}")

        data = r.json()
        choices = data.get("choices") or []
        if not choices:
            return None
        message = choices[0].get("message") or {}
        text = (message.get("content") or "").strip()
        if not text:
            return None
        annotations = message.get("annotations") or []
        search_calls = [
            item
            for item in (data.get("web_search") or annotations)
            if isinstance(item, dict)
        ]

        usage_raw = data.get("usage") or {}
        usage = {
            "input_tokens": usage_raw.get("prompt_tokens"),
            "output_tokens": usage_raw.get("completion_tokens"),
            "total_tokens": usage_raw.get("total_tokens"),
        }
        return {
            "text": text,
            "search_calls": search_calls,
            "usage": usage,
            "elapsed_s": time.time() - t0,
        }

    def _post_gemini_google_search(
        self,
        service_cfg: Dict,
        api_key: str,
        model: str,
        prompt: str,
        timeout_s: int,
    ) -> Optional[Dict]:
        """Use Gemini generateContent with Google Search grounding."""
        base_url = (
            service_cfg.get("base_url")
            or service_cfg.get("native_base_url")
            or service_cfg.get("gemini_base_url")
            or service_cfg.get("google_base_url")
            or "https://generativelanguage.googleapis.com/v1beta"
        )
        base_url = base_url.rstrip("/")

        native_key = (
            service_cfg.get("native_key")
            or service_cfg.get("gemini_api_key")
            or service_cfg.get("google_api_key")
            or (service_cfg.get("native_keys") or [None])[0]
            or (service_cfg.get("google_keys") or [None])[0]
            or api_key
        )
        if not native_key:
            raise RuntimeError("missing Gemini native API key for google_search")

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt},
                    ],
                },
            ],
            "tools": [
                {"google_search": {}},
            ],
            "generationConfig": self._gemini_generation_config(service_cfg),
        }
        headers = {
            "x-goog-api-key": native_key,
            "Content-Type": "application/json",
        }

        t0 = time.time()
        response = requests.post(
            f"{base_url}/models/{model}:generateContent",
            headers=headers,
            json=payload,
            timeout=timeout_s,
        )
        if response.status_code != 200:
            raise RuntimeError(f"HTTP {response.status_code}: {response.text[:500]}")

        data = response.json()
        candidates = data.get("candidates") or []
        text_parts: List[str] = []
        grounding_items: List[Dict] = []
        for candidate in candidates:
            content = candidate.get("content") or {}
            for part in content.get("parts") or []:
                if part.get("text"):
                    text_parts.append(part["text"])
            grounding = candidate.get("groundingMetadata") or {}
            if grounding:
                grounding_items.append(grounding)

        usage_meta = data.get("usageMetadata") or {}
        usage = {
            "input_tokens": usage_meta.get("promptTokenCount"),
            "output_tokens": usage_meta.get("candidatesTokenCount"),
            "total_tokens": usage_meta.get("totalTokenCount"),
        }
        return {
            "text": "\n".join(text_parts).strip(),
            "search_calls": grounding_items,
            "usage": usage,
            "elapsed_s": time.time() - t0,
        }

