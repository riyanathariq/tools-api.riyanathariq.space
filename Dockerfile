FROM golang:1.22-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/tools-api ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/tools-api /tools-api
USER nonroot:nonroot
EXPOSE 3003
ENV HTTP_ADDR=:3003
ENTRYPOINT ["/tools-api"]
