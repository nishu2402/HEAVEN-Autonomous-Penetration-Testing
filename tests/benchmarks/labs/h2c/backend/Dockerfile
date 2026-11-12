# Build-based (COPY, not bind-mount) so the context ships over the Docker socket
# and never hits the colima "operation not permitted" VM-mount gotcha.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -o /h2cserver .

FROM alpine:3.20
COPY --from=build /h2cserver /h2cserver
EXPOSE 80
CMD ["/h2cserver"]
