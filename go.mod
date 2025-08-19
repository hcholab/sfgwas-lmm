module github.com/hhcho/sfgwas-lmm

go 1.18

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da
	github.com/hhcho/frand v1.3.1-0.20210217213629-f1c60c334950
	github.com/hhcho/mpc-core v0.0.0-20220701160924-2e57cff64440
	github.com/ldsec/lattigo/v2 v2.4.0
	github.com/raulk/go-watchdog v1.3.0
	go.dedis.ch/onet/v3 v3.2.3
	golang.org/x/net v0.0.0-20200301022130-244492dfa37a
	gonum.org/v1/gonum v0.9.3
)

require (
	github.com/benbjohnson/clock v1.3.0 // indirect
	github.com/containerd/cgroups v0.0.0-20201119153540-4cbc285b3327 // indirect
	github.com/coreos/go-systemd/v22 v22.1.0 // indirect
	github.com/daviddengcn/go-colortext v0.0.0-20180409174941-186a3d44e920 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/elastic/gosigar v0.12.0 // indirect
	github.com/godbus/dbus/v5 v5.0.3 // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/opencontainers/runtime-spec v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543 // indirect
)

replace github.com/ldsec/lattigo/v2 => github.com/hcholab/lattigo/v2 v2.1.2-0.20220628190737-bde274261547
