TARGET = hello-1
TARGET_DEV = veth-1

# encap.bpf.o: %.o: %.c
# 	clang-17 \
# 		-target bpf \
# 		-I/usr/include/$(shell uname -m)-linux-gnu \
# 		-g \
# 		-O2 -c $< -o $@

# decap.bpf.o: %.o: %.c
# 	clang-17 \
# 		-target bpf \
# 		-I/usr/include/$(shell uname -m)-linux-gnu \
# 		-g \
# 		-O2 -c $< -o $@

default: 
	clang-17 \
		-target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
		-O2 -c encap.bpf.c -o encap.bpf.o
	clang-17 \
		-target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
		-O2 -c decap.bpf.c -o decap.bpf.o
	bpftool net detach xdpgeneric dev veth-1
	rm -f /sys/fs/bpf/encap
	bpftool prog load encap.bpf.o /sys/fs/bpf/encap
	bpftool net attach xdpgeneric pinned /sys/fs/bpf/encap dev veth-1
	bpftool net detach xdpgeneric dev eth0
	rm -f /sys/fs/bpf/decap
	bpftool prog load decap.bpf.o /sys/fs/bpf/decap
	bpftool net attach xdpgeneric pinned /sys/fs/bpf/decap dev eth0

# decap: 
# 	bpftool net detach xdpgeneric dev eth0
# 	rm -f /sys/fs/bpf/decap
# 	bpftool prog load decap.bpf.o /sys/fs/bpf/decap
# 	bpftool net attach xdpgeneric pinned /sys/fs/bpf/decap dev eth0

clean:
	bpftool net detach xdpgeneric dev eth0
	bpftool net detach xdpgeneric dev veth-1
	rm -f /sys/fs/bpf/encap
	rm -f /sys/fs/bpf/decap
	echo > /sys/kernel/debug/tracing/trace