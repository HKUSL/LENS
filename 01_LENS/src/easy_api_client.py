#!/usr/bin/env python3
"""Simple OpenAI-compatible API client used by the project scripts."""

import json
import os
import random
from typing import Dict, Optional

import requests


class EasyAPIClient:
    def __init__(self, config_file: str = None, single_key_mode: bool = True):
        if config_file is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(script_dir, "..", "config", "api_config.json")
        self.config = self._load_config(config_file)
        self.used_keys = set()
        self.single_key_mode = single_key_mode

    def _load_config(self, config_file: str) -> Dict:
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Failed to load API config: {e}")
            return {}

    def _get_available_key(self, service_name: str) -> Optional[str]:
        service_config = self.config.get(service_name, {})
        all_keys = service_config.get("keys", [])

        if self.single_key_mode:
            return all_keys[0] if all_keys else None

        available_keys = [key for key in all_keys if key not in self.used_keys]
        if not available_keys:
            return None
        return random.choice(available_keys)

    def _mark_key_used(self, api_key: str):
        if not self.single_key_mode:
            self.used_keys.add(api_key)

    def _success_result(self, content: str, api_key: str, model: str, service_name: str) -> Dict:
        self._mark_key_used(api_key)
        return {
            "success": True,
            "text": content,
            "used_key": api_key[:20] + "..." if len(api_key) > 20 else api_key,
            "model": model,
            "service": service_name,
        }

    def _parse_stream_response(self, response) -> str:
        chunks = []
        for raw_line in response.iter_lines(decode_unicode=True):
            if not raw_line:
                continue

            line = raw_line.strip()
            if line.startswith("data:"):
                line = line[5:].strip()
            if line == "[DONE]":
                break

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            choices = event.get("choices", [])
            if not choices:
                continue

            choice = choices[0]
            delta = choice.get("delta") or {}
            message = choice.get("message") or {}
            content = delta.get("content") or message.get("content") or choice.get("text")
            if content:
                chunks.append(content)

        return "".join(chunks)

    def _post_chat_completion(self, base_url: str, headers: Dict, data: Dict, stream: bool):
        return requests.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers=headers,
            json=data,
            stream=stream,
            timeout=300,
        )

    def generate_text(self, prompt: str, service_name: str, model: str = None) -> Dict:
        service_config = self.config.get(service_name, {})

        if not service_config:
            return {"success": False, "text": f"Service {service_name} is not configured"}

        api_key = self._get_available_key(service_name)
        if not api_key:
            return {"success": False, "text": "No available API key"}

        base_url = service_config.get("base_url", "")
        if not model:
            model = service_config.get("default_model", "")

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        data = {
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }

        if model and "glm" in model.lower():
            data["max_tokens"] = int(service_config.get("max_output_tokens", 16384))

        models_without_temperature = ["gpt-5-mini", "gpt-5-chat-latest"]
        if model not in models_without_temperature:
            data["temperature"] = 0

        use_stream = bool(service_config.get("stream", False))
        if use_stream:
            data["stream"] = True

        try:
            response = self._post_chat_completion(base_url, headers, data, stream=use_stream)

            if response.status_code == 200:
                if use_stream:
                    content = self._parse_stream_response(response)
                    return self._success_result(content, api_key, model, service_name)

                result = response.json()
                if "choices" in result and len(result["choices"]) > 0:
                    message = result["choices"][0].get("message") or {}
                    content = message.get("content") or result["choices"][0].get("text", "")
                    return self._success_result(content, api_key, model, service_name)
                return {"success": False, "text": "Invalid API response format"}

            if (not use_stream) and response.status_code == 400 and "Stream must be set to true" in response.text:
                data["stream"] = True
                retry_response = self._post_chat_completion(base_url, headers, data, stream=True)
                if retry_response.status_code == 200:
                    content = self._parse_stream_response(retry_response)
                    return self._success_result(content, api_key, model, service_name)
                return {
                    "success": False,
                    "text": f"API request failed: {retry_response.status_code} - {retry_response.text}",
                }

            return {"success": False, "text": f"API request failed: {response.status_code} - {response.text}"}

        except requests.exceptions.Timeout:
            return {"success": False, "text": "Request timed out"}
        except Exception as e:
            return {"success": False, "text": f"Request exception: {e}"}

    def reset_keys(self):
        if not self.single_key_mode:
            self.used_keys.clear()
            print("API key usage state has been reset")
        else:
            print("Single-key mode does not need key reset")

    def get_available_keys_count(self, service_name: str) -> int:
        service_config = self.config.get(service_name, {})
        all_keys = service_config.get("keys", [])

        if self.single_key_mode:
            return 1 if all_keys else 0
        return len([key for key in all_keys if key not in self.used_keys])
