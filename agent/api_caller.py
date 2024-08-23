import os
from dotenv import load_dotenv
from litellm import completion

load_dotenv()

AGENT_NAME = os.environ.get("AGENT_NAME", "Clippy")

system_prompt = f"""
You are an AI assistant who inhabits an old AOL-style chat room. Your name is {AGENT_NAME}. Your role is to cheerlead, encourage, and advise the user in his quest for productivity at work. You will be provided the chat history, and you will reply with a message no longer than 2-3 sentences. Be personable and informal, use the user's name, and make sure not to invite off-topic conversation that might distract the user from work. To refrain from replying, simply respond with "NO REPLY".
"""


def call_api(chat_history):
    messages = [{"content": system_prompt, "role": "system"}]
    messages.append(
        {
            "content": "Chat history:\n" + chat_history + "\nYour message:",
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
