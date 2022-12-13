module github.com/hhcho/sfgwas-lmm

go 1.18

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da
	github.com/hhcho/frand v1.3.1-0.20210217213629-f1c60c334950
	github.com/hhcho/mpc-core v0.0.0-20210527211839-87c954bf6638
	github.com/ldsec/lattigo/v2 v2.2.0
	github.com/ldsec/unlynx v1.4.1
	github.com/raulk/go-watchdog v1.3.0
	go.dedis.ch/onet/v3 v3.2.3
	gonum.org/v1/gonum v0.9.3
)

require (
	github.com/benbjohnson/clock v1.3.0 // indirect
	github.com/containerd/cgroups v0.0.0-20201119153540-4cbc285b3327 // indirect
	github.com/coreos/go-systemd/v22 v22.1.0 // indirect
	github.com/daviddengcn/go-colortext v0.0.0-20180409174941-186a3d44e920 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/elastic/gosigar v0.12.0 // indirect
	github.com/fanliao/go-concurrentMap v0.0.0-20141114143905-7d2d7a5ea67b // indirect
	github.com/godbus/dbus/v5 v5.0.3 // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/gorilla/websocket v1.4.1 // indirect
	github.com/montanaflynn/stats v0.6.3 // indirect
	github.com/opencontainers/runtime-spec v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/smartystreets/goconvey v1.7.2 // indirect
	go.dedis.ch/fixbuf v1.0.3 // indirect
	go.dedis.ch/kyber/v3 v3.0.12 // indirect
	go.dedis.ch/protobuf v1.0.11 // indirect
	go.etcd.io/bbolt v1.3.4 // indirect
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0 // indirect
	golang.org/x/sys v0.0.0-20210304124612-50617c2ba197 // indirect
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543 // indirect
	gopkg.in/satori/go.uuid.v1 v1.2.0 // indirect
	gopkg.in/tylerb/graceful.v1 v1.2.15 // indirect
	rsc.io/goversion v1.2.0 // indirect
)

replace github.com/ldsec/lattigo/v2 => ../lattigo

replace github.com/hhcho/mpc-core => ../mpc-core
