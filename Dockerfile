FROM golang:1.23 AS builder

WORKDIR /code
COPY go.mod go.sum /code/
RUN go mod download

COPY . /code
RUN CGO_ENABLED=0 GOOS=linux go build -o /tink-stack .

FROM scratch

COPY --from=builder /tink-stack /tink-stack
ENTRYPOINT [ "/tink-stack" ]