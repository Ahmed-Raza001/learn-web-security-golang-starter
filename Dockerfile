# Stage 1: Build
FROM golang:1.27.0-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN mkdir -p /out

RUN CGO_ENABLED=0 go build -trimpath -o /out/bearly-secure ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -o /out/bearly-attacker-lab ./cmd/attackerlab

# Stage 2: Runtime
FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && addgroup -S bearly \
    && adduser -S -G bearly bearly

WORKDIR /app

# Copy only required binaries
COPY --from=build /out/bearly-secure ./bearly-secure
COPY --from=build /out/bearly-attacker-lab ./bearly-attacker-lab

# Copy required application assets
COPY attacker-lab/ ./attacker-lab/
COPY web/ ./web/
COPY data/uploads/mystery-shack-tax-exemption.pdf ./data/uploads/mystery-shack-tax-exemption.pdf

# Give bearly ownership of data directory
RUN mkdir -p /app/data \
    && chown -R bearly:bearly /app/data

# Run as unprivileged user
USER bearly

CMD ["./bearly-secure"]


COPY data/fixtures ./data/fixtures