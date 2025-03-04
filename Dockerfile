FROM python:3.12-slim
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy over code and tests
COPY x25519/ x25519/
COPY ed25519/ ed25519/
COPY tests/ tests/

# Copy the test runner script
COPY run_tests.sh .
RUN chmod +x run_tests.sh

ENTRYPOINT ["./run_tests.sh"]
