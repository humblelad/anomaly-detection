FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
COPY ja4/ ./ja4/
RUN CGO_ENABLED=0 go build -o /ja4-sidecar .

FROM gcr.io/distroless/static-debian12
COPY --from=build /ja4-sidecar /ja4-sidecar
EXPOSE 8443
ENTRYPOINT ["/ja4-sidecar"]
