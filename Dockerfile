# TODO: Allow the user to specify to spin up server, client, or agent containers on different ports

# Use Python 3.12
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install poetry
RUN pipx install poetry

# Copy poetry files
COPY pyproject.toml poetry.lock ./

# Copy necessary folders and files
COPY utils /app/utils
COPY agent /app/agent

# Install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi

# Set the entrypoint
ENTRYPOINT ["sh", "-c", "poetry run python -m agent.agent"]