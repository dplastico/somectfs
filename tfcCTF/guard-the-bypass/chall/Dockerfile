FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    socat \
    libstdc++6 \
    libgcc-s1 \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /home/ctf

COPY guard /home/ctf/guard
COPY flag.txt /home/ctf/flag.txt
COPY libc.so.6 /home/ctf/libc.so.6
COPY ld-2.35.so /home/ctf/ld-2.35.so

RUN chmod +x /home/ctf/guard

WORKDIR /home/ctf

EXPOSE 1337

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/home/ctf/guard
