export GOPATH=`pwd`
mkdir -p bin

os=$1
arch=$2
prg=$3

GOOS=$os GOARCH=$arch go build -o bin/l2t-server${os}${arch} -ldflags \
"-extldflags '-static' -X main.buildTime=`date +%Y%m%d/%H:%M:%S`" \
src/mytun/vl2Server.go

GOOS=$os GOARCH=$arch go build -o bin/l2t-tun${os}${arch} -ldflags \
"-extldflags '-static' -X main.buildTime=`date +%Y%m%d/%H:%M:%S`" \
src/mytun/tun.go

GOOS=linux GOARCH=arm go build -o bin/l2t-tun-arm -ldflags \
"-extldflags '-static' -X main.buildTime=`date +%Y%m%d/%H:%M:%S`" src/mytun/tun.go
