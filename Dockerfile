FROM golang:stretch as build
RUN mkdir /go/src/WifiRegistration
WORKDIR /go/src/WifiRegistration
COPY . /go/src/WifiRegistration
RUN go get .
RUN go build

FROM debian:stretch
RUN mkdir /app
COPY --from=build /go/src/WifiRegistration/WifiRegistration /app/registration
ENTRYPOINT /app/registration
