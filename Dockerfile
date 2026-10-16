# syntax=docker/dockerfile:1

FROM node:22-alpine AS assets
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
COPY internal/ ../internal/
RUN npm run build

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=assets /src/web/static/dist ./web/static/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X lemongate/internal/app.Version=${VERSION}" -o /out/lemongate ./cmd/lemongate \
 && CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/mockvllm ./cmd/mockvllm

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/lemongate /usr/local/bin/lemongate
COPY --from=build /out/mockvllm /usr/local/bin/mockvllm
EXPOSE 4000
USER nonroot
ENTRYPOINT ["/usr/local/bin/lemongate"]
CMD ["serve"]
