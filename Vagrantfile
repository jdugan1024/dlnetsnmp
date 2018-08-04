# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "base"
  config.vm.box = "geerlingguy/centos7"
  config.vm.box_version = "1.2.8"

  config.ssh.insert_key = false
  config.vm.hostname = "fusnmp-vagrant"
  config.vm.provision "shell", inline: <<-SHELL
    yum install -y \
      net-snmp net-snmp-agent-libs net-snmp-devel net-snmp-libs net-snmp-utils \
      python-virtualenv \
      rpm-build \
      epel-release
    yum install -y tito

  SHELL
end
