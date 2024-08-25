import os
import logging
from dotenv import load_dotenv
from litellm import completion

logger = logging.getLogger(__name__)

load_dotenv(override=True)

AGENT_USERNAME = os.environ.get("AGENT_USERNAME", "Clippy")

system_prompt = f"""
You are an AI assistant who inhabits an old AOL-style chat room. Your name is {AGENT_USERNAME}. Your role is to cheerlead, encourage, and advise the user in his quest for productivity at work. You will be provided the chat history, and you will reply with a message no longer than 2-3 sentences. Be personable and informal, use the user's name, and make sure not to invite off-topic conversation that might distract the user from work. To refrain from replying, simply respond with "NO REPLY".
"""


def format_chat_history(chat_history: list[tuple[str, str]]) -> str:
    return "\n\n".join([f"{header}\n{message}" for header, message in chat_history])


def call_api(chat_history: list[tuple[str, str]]) -> str:
    messages = [{"content": system_prompt, "role": "system"}]
    messages.append(
        {
            "content": "Chat history:\n"
            + format_chat_history(chat_history)
            + "\nYour message:",
            "role": "user",
        }
    )

    response = completion(
        model="gpt-4o-mini",
        messages=messages,
        api_key=os.getenv("LLM_PROVIDER_API_KEY"),
    )

    if response.choices[0].message.content == "NO REPLY":
        return None

    return response.choices[0].message.content
