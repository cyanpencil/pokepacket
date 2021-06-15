FROM golang:1.16

WORKDIR /go/src/pokepacket

RUN apt-get update && apt-get install -y libpcap0.8-dev

COPY main.go go.mod ./
COPY layout/ ./layout/

RUN go get -d -v ./...

RUN go build -v .
