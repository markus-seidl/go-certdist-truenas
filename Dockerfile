FROM alpine:latest

ARG TARGETPLATFORM

WORKDIR /

COPY build/${TARGETPLATFORM}/certdist-truenas /certdist-truenas
COPY build/exec.sh /exec.sh
COPY build/wait.sh /wait.sh
COPY build/entrypoint.sh /entrypoint.sh

RUN chmod +x /exec.sh && chmod +x /wait.sh && chmod +x /entrypoint.sh && chmod +x /certdist-truenas

# Run the application once, to ensure we have the correct setup/platform/executable
RUN /certdist-truenas && true

# The command to run the application
# The user will need to provide the command-line arguments (e.g., "server", "config.yml")
CMD ["/entrypoint.sh"]

