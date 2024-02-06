FLUENT_BIT?=/opt/fluent-bit/bin/fluent-bit

all: out_deepfence.a

deepfence.o: deepfence.c out_deepfence.h
	gcc  -I ../../lib/msgpack-c/include -I ../../lib/mpack-amalgamation-1.1/src -I ../../lib/ctraces/include -I ../../lib/cfl/lib/xxhash -I ../../lib/cfl/include/ -I ../../lib/cmetrics/include/ -I ../../lib/c-ares-1.19.0/include/ -I ../../lib/flb_libco/ -I ../../build/lib/monkey/include/monkey -I ../../lib/monkey/include -I ../../include -c deepfence.c -o deepfence.o

.PHONY: vendor
vendor:
	go mod tidy -v
	go mod vendor

out_deepfence.h: vendor out_deepfence.go
	go build -buildmode=c-archive -o out_deepfence.a out_deepfence.go

out_deepfence.a: vendor  deepfence.o
	ar r out_deepfence.a deepfence.o

clean:
	-rm ./*.so
	-rm ./*.a
	-rm ./*.o
	-rm out_deepfence.h
	-rm -rf ./vendor

docker:
	docker build -t fluentbit:deepfence .

run: all
	$(FLUENT_BIT) -c local-fluent-bit.conf
