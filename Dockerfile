# build stage
FROM golang:alpine AS builder
WORKDIR /app
COPY . .
RUN go env -w GO111MODULE=on \
    && go env -w GOPROXY=https://goproxy.cn,direct \
    && go get -d -v . \
    && go install -v . \
    && go build -v .

# final stage
FROM alpine
WORKDIR /app
RUN apk add --no-cache tzdata
ENV TZ=Asia/Shanghai
COPY --from=builder /app/rerun_frp /app/rerun_frp
COPY frpThings /app/frpThings
ENTRYPOINT /app/rerun_frp
LABEL Name=rerun_frp Version=0.0.1
