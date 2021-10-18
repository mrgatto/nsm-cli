FROM python:3.7.9-alpine3.12

WORKDIR /root/nsm-cli

COPY nsm-cli .
COPY nsm_cli_exec.py .
COPY vsock.py .

CMD ["/usr/local/bin/python3", "/root/nsm-cli/nsm_cli_exec.py", "server", "3000"]

