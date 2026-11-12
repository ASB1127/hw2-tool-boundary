from config import Config
from tools import ToolBundle


def _adapter(chat_model, config: Config, output_option: str):
    model = chat_model(model=config.model["name"]).bind_tools(ToolBundle.get_all_tools())

    def invoke_model(*, messages, output_allowance):
        return model.bind(**{output_option: output_allowance}).invoke(messages)

    return invoke_model


def _ollama_adapter(chat_model, config: Config):
    def invoke_model(*, messages, output_allowance):
        model = chat_model(
            model=config.model["name"], num_predict=output_allowance,
            reasoning=True, temperature=0,
        ).bind_tools(ToolBundle.get_all_tools())
        return model.invoke(messages)

    return invoke_model


def model(config: Config):
    provider = config.model["provider"]
    if provider == "openai":
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as error:
            raise RuntimeError("langchain-openai is required for the OpenAI provider") from error
        return _adapter(ChatOpenAI, config, "max_tokens")
    if provider == "ollama":
        try:
            from langchain_ollama import ChatOllama
        except ImportError as error:
            raise RuntimeError("langchain-ollama is required for the Ollama provider") from error
        return _ollama_adapter(ChatOllama, config)
    raise RuntimeError(f"unsupported model provider: {provider}")
