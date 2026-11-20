from config import Config


def _model_tools(tools: dict) -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": tool.description or "",
                "parameters": tool.input_schema,
            },
        }
        for name, tool in tools.items()
    ]


def _adapter(chat_model, config: Config, output_option: str, tools: dict):
    model = chat_model(model=config.model["name"]).bind_tools(_model_tools(tools))

    def invoke_model(*, messages, output_allowance):
        return model.bind(**{output_option: output_allowance}).invoke(messages)

    return invoke_model


def _ollama_adapter(chat_model, config: Config, tools: dict):
    def invoke_model(*, messages, output_allowance):
        model = chat_model(
            model=config.model["name"], num_predict=output_allowance,
            reasoning=True, temperature=0,
        ).bind_tools(_model_tools(tools))
        return model.invoke(messages)

    return invoke_model


def model(config: Config, tools: dict):
    provider = config.model["provider"]
    if provider == "openai":
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as error:
            raise RuntimeError("langchain-openai is required for the OpenAI provider") from error
        return _adapter(ChatOpenAI, config, "max_tokens", tools)
    if provider == "ollama":
        try:
            from langchain_ollama import ChatOllama
        except ImportError as error:
            raise RuntimeError("langchain-ollama is required for the Ollama provider") from error
        return _ollama_adapter(ChatOllama, config, tools)
    raise RuntimeError(f"unsupported model provider: {provider}")
