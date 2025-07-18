"""OpenAIService
基于 `openai` 官方 SDK 的服务实现。

This provider connects NexusAI to **OpenAI Chat Completions API** and supports
both *stream* and *non-stream* interactions.  It is registered through
``@register_provider("openai")`` so that :pyfunc:`AIService.get_provider_class`
can discover it by name.
"""

import threading
import time
from typing import Any

from ..Config.config import ConfigManager
from .base_service import BaseAIService, QueryStatus
from . import register_provider

@register_provider("openai")
class OpenAIService(BaseAIService):
    """处理与 OpenAI API 的通信。
    Handles communication with the OpenAI API.
    """

    def __init__(self, config_manager: ConfigManager):
        super().__init__(config_manager)
        self.stop_event = threading.Event()

    def query_stream(self, prompt: str):
        """以流式方式执行 AI 查询，并将结果实时推送到 UI。
        Executes an AI query in streaming mode and pushes the results to the UI in real-time.
        """
        if not self.is_client_initialized():
            self.config.show_message("client_not_initialized_check")
            return

        self.stop_event.clear()

        attempts = 0
        while attempts < 2:
            try:
                self.config.show_message("sending_request")
                self.config.show_message("ai_response_header")
                if self.config.output_view:
                    self.config.output_view.append_text("<hr/>")
                    self.config.output_view.append_text("<div style='margin: 0; padding: 0;'></div>")

                messages = self.create_prompt("system", prompt)

                response_stream = self.config.client.chat.completions.create(
                    model=self.config.model_name,
                    messages=messages,
                    stream=True,
                )

                full_response: list[str] = []
                self.config.show_empty_line()
                self.config.start_stream_response()

                for chunk in response_stream:
                    if self.stop_event.is_set():
                        self.config.show_message("aimcp_cancelled")
                        break

                    if (
                        chunk.choices
                        and chunk.choices[0].delta
                        and chunk.choices[0].delta.content
                    ):
                        content = chunk.choices[0].delta.content
                        full_response.append(content)
                        self.config.show_stream_chunk(content)

                full_response_str = "".join(full_response)
                if not self.stop_event.is_set() and full_response_str.strip():
                    self.config.finalize_stream_response(full_response_str)

                break
            except Exception as e:  # noqa: BLE001
                attempts += 1
                err_msg = str(e)

                if attempts < 2 and (
                    "429" in err_msg
                    or "rate limit" in err_msg.lower()
                    or "负载" in err_msg
                ):
                    self.config.show_message(
                        "openai_request_error",
                        f"{err_msg} - retrying in 5s ({attempts}/1)",
                    )
                    time.sleep(5)
                    continue

                self.config.show_message("openai_request_error", err_msg)
                break

        if not self.stop_event.is_set():
            if self.config.output_view:
                self.config.output_view.append_text("<hr/>")
                self.config.output_view.append_text("<div style='margin: 0; padding: 0;'></div>")
            self.config.show_message("analysis_complete")

    def create_prompt(self, prompt_type: str, content: str):  # noqa: D401
        """兼容旧逻辑的提示词构造函数。
        Prompt constructor for backward compatibility.
        """
        try:
            current_lang = self.config.language
            prompt = (
                self.config.get_prompt_by_type(prompt_type)
                if prompt_type
                else self.config.prompt
            )

            messages: list[dict[str, Any]] = [{"role": "system", "content": prompt}]

            if content:
                lang_indicator = (
                    "请用中文回复" if current_lang == "zh_CN" else "Please reply in English"
                )
                user_content = f"{content}\n\n{lang_indicator}"
                messages.append({"role": "user", "content": user_content})

            return messages
        except Exception as e:  # noqa: BLE001
            self.config.show_message("create_prompt_error", str(e))
            return [{"role": "system", "content": self.config.prompt}]

    def query(self, messages):
        """非流式一次性查询，保持向后兼容。
        Non-streaming one-time query for backward compatibility.
        """
        if not self.is_client_initialized():
            self.config.show_message("client_not_initialized_check")
            return None

        attempts = 0
        while attempts < 2:
            try:
                completion = self.config.client.chat.completions.create(
                    model=self.config.model_name,
                    messages=messages,
                )
                if completion.choices:
                    return completion.choices[0].message.content
                return ""
            except Exception as e:  # noqa: BLE001
                attempts += 1
                err_msg = str(e)

                if attempts < 2 and (
                    "429" in err_msg
                    or "rate limit" in err_msg.lower()
                    or "负载" in err_msg
                ):
                    self.config.show_message(
                        "openai_request_error",
                        f"{err_msg} - retrying in 5s ({attempts}/1)",
                    )
                    time.sleep(5)
                    continue

                self.config.show_message("openai_request_error", err_msg)
                return None

        return None 