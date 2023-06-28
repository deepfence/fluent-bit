FLUENT_BIT?=/opt/fluent-bit/bin/fluent-bit

all: out_deepfence.so out_deepfence.a

out_deepfence.so: ./*.go
	go mod tidy -v
	go build -buildmode=c-shared -o out_deepfence.so

out_deepfence.a: ./*.go
	go mod tidy -v
	go build -buildmode=c-archive -o out_deepfence.a

clean:
	-rm ./*.h
	-rm ./*.so
	-rm ./*.a

docker:
	docker build -t fluentbit:deepfence .

run: all
	$(FLUENT_BIT) -c local-fluent-bit.conf
