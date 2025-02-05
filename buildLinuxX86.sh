#!/usr/bin/env zsh

# 设置环境变量
export GOOS=linux
export GOARCH=amd64

# 获取当前的日期和时间，格式为YYYYMMDDHHMM
current_datetime=$(date +%Y%m%d%H%M)

# 定义输出文件名，加入日期时间
output_file="./rerun_frp_linux_x64_${current_datetime}"

# 编译并输出到指定文件名
go build -o "${output_file}"

# 打印生成的文件名（可选）
echo "Build output: ${output_file}"