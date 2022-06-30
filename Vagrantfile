# Read the branch's Go version from the .go-version file.
GO_VERSION = File.read(File.join(File.dirname(__FILE__), ".go-version")).strip

Vagrant.configure("2") do |config|
  config.vm.provider :virtualbox do |vbox|
    vbox.memory = 8192
    vbox.cpus = 6
  end

    config.vm.define "fleet-dev" do |nodeconfig|
      nodeconfig.vm.box = "ubuntu/impish64"

      nodeconfig.vm.hostname = "fleet-server-dev"

      nodeconfig.vm.network "private_network",
        hostname: true,
        ip: "192.168.56.43" # only 192.168.56.0/21 range allowed: https://www.virtualbox.org/manual/ch06.html#network_hostonly
      nodeconfig.vm.network "forwarded_port", guest: 4243, host: 4243, id: "delve"
      nodeconfig.vm.network "forwarded_port", guest: 8220, host: 8220, id: "fleet-server"

      # fleet-server needs the agent, so let's mount it all
      nodeconfig.vm.synced_folder "../", "/vagrant"
      nodeconfig.vm.provider "virtualbox" do |vb|
        # Display the VirtualBox GUI when booting the machine
        vb.gui = false
        vb.customize ["modifyvm", :id, "--vram", "128"]
        # Customize the amount of memory on the VM:
        vb.memory = "2048"
      end
      $user_script = <<-SCRIPT
        GOPATH=$(go env GOPATH) # use Go's default
        mkdir -p $GOPATH/src/github.com/magefile
        cd $GOPATH/src/github.com/magefile
        git clone https://github.com/magefile/mage.git
        cd $GOPATH/src/github.com/magefile/mage
        go run bootstrap.go
      SCRIPT

      nodeconfig.vm.provision "root-shell", type: "shell", inline: <<-SHELL
         apt-get update
         apt-get install -y \
          build-essential \
          curl \
          delve \
          make \
          unzip
          vim \
          wget \
          zip
         curl -sL -o /tmp/go#{GO_VERSION}.linux-amd64.tar.gz https://go.dev/dl/go#{GO_VERSION}.linux-amd64.tar.gz
         tar -C /usr/local -xzf /tmp/go#{GO_VERSION}.linux-amd64.tar.gz
         echo "alias ll='ls -la'" > /etc/profile.d/ll.sh
         echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
         echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> /etc/profile.d/go.sh
         curl -sL -o /tmp/mage.tar.gz https://github.com/magefile/mage/releases/download/v1.13.0/mage_1.13.0_Linux-64bit.tar.gz
         tar -xf /tmp/mage.tar.gz
         mv mage /usr/local/bin
      SHELL
    end

end
