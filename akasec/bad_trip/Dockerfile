FROM archlinux


RUN pacman -Sy
RUN pacman -S --noconfirm socat

EXPOSE 1352

WORKDIR /chal
COPY bad_trip /chal
COPY flag.txt /chal

CMD ["socat", "tcp-l:1352,reuseaddr,fork", "EXEC:./bad_trip"]
