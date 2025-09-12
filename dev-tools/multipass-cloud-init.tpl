apt:
  sources:
    docker.list:
      source: deb [arch={{.Arch}}] https://download.docker.com/linux/ubuntu noble stable
      keyid: 9DC858229FC7DD38854AE2D88D81803C0EBFCD88
groups:
  - docker
system_info:
  default_user:
    groups: [docker]
package_update: true
package_upgrade: true
packages:
  - make
  - gcc
  - git
  - openssl
  - ca-certificates
  - curl
  - gnupg
  - docker-ce
  - docker-ce-cli
  - containerd.io
  - docker-buildx-plugin
  - docker-compose-plugin
  - unzip
  - zip
write_files:
  - content: |
      export PATH=$PATH:/usr/local/go/bin
      export PATH=$PATH:$(go env GOPATH)/bin
    path: /etc/profile.d/go-bin.sh
runcmd:
  - [ mkdir, /run/go ]
  - [ wget, {{.DownloadURL}}, -O, /run/go/go.tar.gz ]
  - [ tar, -xzf, /run/go/go.tar.gz, -C, /usr/local/ ]
  - [ rm, -rf, /run/go ]
  - [ su, ubuntu, -c, "/usr/local/go/bin/go install github.com/magefile/mage@latest" ]
  - [ su, ubuntu, -c, "/usr/local/go/bin/go install github.com/go-delve/delve/cmd/dlv@latest" ]

