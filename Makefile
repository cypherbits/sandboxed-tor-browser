CC	:= gcc
CFLAGS	:= -Os -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-all -Wstack-protector --param ssp-buffer-size=1 -fPIC -Wall -Werror -Wextra -Wl,-z,relro,-z,now

GTK3TAG := gtk_3_14

all: sandboxed-tor-browser

sandboxed-tor-browser: static-assets
	gb build -tags $(GTK3TAG) cmd/sandboxed-tor-browser
	mv ./bin/sandboxed-tor-browser-$(GTK3TAG) ./bin/sandboxed-tor-browser

static-assets: go-bindata tbb_stub
	git rev-parse --short HEAD > data/revision
	./bin/go-bindata -nometadata -pkg data -prefix data -o ./src/cmd/sandboxed-tor-browser/internal/data/bindata.go data/...

tbb_stub: go-bindata
	$(CC) -shared -pthread $(CFLAGS) src/tbb_stub/tbb_stub.c -o data/tbb_stub.so

go-bindata:
	gb build github.com/jteeuwen/go-bindata/go-bindata

clean:
	rm -f ./src/cmd/sandboxed-tor-browser/internal/data/bindata.go
	rm -f ./data/revision
	rm -f ./data/tbb_stub.so
	rm -f ./data/*.bpf
	rm -Rf ./bin
	rm -Rf ./pkg
