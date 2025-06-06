# Read the branch's Go version from the .go-version file.
GO_VERSION = File.read(File.join(File.dirname(__FILE__), ".go-version")).strip

Vagrant.configure("2") do |config|
  config.vm.provider :virtualbox do |vbox|
    vbox.memory = 8192
    vbox.cpus = 6
  end

  # require plugin https://github.com/leighmcculloch/vagrant-docker-compose
  # vagrant plugin install vagrant-docker-compose
  config.vagrant.plugins = "vagrant-docker-compose"

  # install docker and docker-compose
  config.vm.provision :docker
  config.vm.provision :docker_compose

    config.vm.define "fleet-dev" do |nodeconfig|
      nodeconfig.vm.box = "ubuntu/jammy64"

      nodeconfig.vm.hostname = "fleet-server-dev"

      nodeconfig.vm.network "private_network",
        hostname: true,
        ip: "192.168.56.43" # only 192.168.56.0/21 range allowed: https://www.virtualbox.org/manual/ch06.html#network_hostonly
      nodeconfig.vm.network "forwarded_port", guest: 4243, host: 4243, id: "delve"
      nodeconfig.vm.network "forwarded_port", guest: 8220, host: 8220, id: "fleet-server"

      # fleet-server needs the agent, so let's mount it all
      nodeconfig.vm.synced_folder "../", "/vagrant"
      nodeconfig.vm.provider "virtualbox" do |vb|
        vb.gui = false
        vb.memory = 8192
        vb.cpus = 2
        vb.customize ["modifyvm", :id, "--ioapic", "on"]
      end

      nodeconfig.vm.provision "shell", inline: <<-SHELL
         apt-get update
         apt-get upgrade -y
         apt-get install -y \
          build-essential \
          curl \
          delve \
          make \
          unzip \
          vim \
          wget \
          zip
         curl -sL -o /tmp/go#{GO_VERSION}.linux-amd64.tar.gz https://go.dev/dl/go#{GO_VERSION}.linux-amd64.tar.gz
         tar -C /usr/local -xzf /tmp/go#{GO_VERSION}.linux-amd64.tar.gz
         echo "alias ll='ls -la'" > /etc/profile.d/ll.sh
         echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
         echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> /etc/profile.d/go.sh
         cd /vagrant/fleet-server; go install github.com/magefile/mage
      SHELL
      nodeconfig.vm.provision "shell", reboot: true
    end

end
