FROM golang:stretch as build
RUN mkdir /go/src/WifiRegistration
WORKDIR /go/src/WifiRegistration
COPY . /go/src/WifiRegistration
RUN go get .
RUN go build

FROM debian:stretch
RUN mkdir /app
COPY --from=build /go/src/WifiRegistration/WifiRegistration /app/registration
COPY *.html /app/
RUN useradd -M -d /app app && \
    chown -R app:app /app
USER app
WORKDIR /app
EXPOSE 3000
ENTRYPOINT ["/app/registration", "--listen-port", "3000"]
