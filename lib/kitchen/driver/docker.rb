# -*- encoding: utf-8 -*-
#
# Copyright (C) 2014, Sean Porter
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'kitchen'
require 'json'
require 'securerandom'
require 'uri'
require 'net/ssh'
require 'tempfile'
require 'shellwords'
require 'base64'
require 'docker'

require 'kitchen/driver/base'

require_relative './docker/erb'

module Kitchen
  module Driver
    # Docker driver for Kitchen.
    #
    # @author Sean Porter <portertech@gmail.com>
    class Docker < Kitchen::Driver::Base
      include ShellOut

      default_config :socket,        ENV['DOCKER_HOST'] || 'unix:///var/run/docker.sock'
      default_config :privileged,    false
      default_config :cap_add,       nil
      default_config :cap_drop,      nil
      default_config :security_opt,  nil
      default_config :use_cache,     true
      default_config :remove_images, false
      default_config :run_command,   '/usr/sbin/sshd -D -o UseDNS=no -o UsePAM=no -o PasswordAuthentication=yes ' +
                                     '-o UsePrivilegeSeparation=no -o PidFile=/tmp/sshd.pid'
      default_config :username,      'kitchen'
      default_config :tls,           false
      default_config :tls_verify,    false
      default_config :tls_cacert,    nil
      default_config :tls_cert,      nil
      default_config :tls_key,       nil
      default_config :publish_all,   false
      default_config :wait_for_sshd, true
      default_config :private_key,   File.join(Dir.pwd, '.kitchen', 'docker_id_rsa')
      default_config :public_key,    File.join(Dir.pwd, '.kitchen', 'docker_id_rsa.pub')
      default_config :build_options, nil
      default_config :run_options,   nil
      default_config :use_internal_docker_network, false

      default_config :use_sudo, false

      default_config :image do |driver|
        driver.default_image
      end

      default_config :platform do |driver|
        driver.default_platform
      end

      default_config :disable_upstart, true

      default_config :build_context do |driver|
        !driver.remote_socket?
      end

      default_config :instance_name do |driver|
        # Borrowed from kitchen-rackspace
        [
          driver.instance.name.gsub(/\W/, ''),
          (Etc.getlogin || 'nologin').gsub(/\W/, ''),
          Socket.gethostname.gsub(/\W/, '')[0..20],
          Array.new(8) { rand(36).to_s(36) }.join
        ].join('-')
      end

      MUTEX_FOR_SSH_KEYS = Mutex.new

      def initialize(config = {})
        super
        @docker_api = ::Docker::Connection.new(config[:socket], {})
        ::Docker.logger = logger
        info("Docker API connection: #{@docker_api}")
      end

      def default_image
        platform, release = instance.platform.name.split('-')
        if platform == 'centos' && release
          release = 'centos' + release.split('.').first
        end
        release ? [platform, release].join(':') : platform
      end

      def default_platform
        instance.platform.name.split('-').first
      end

      def create(state)
        generate_keys
        state[:username] = config[:username]
        state[:ssh_key] = config[:private_key]
        state[:image_id] = build_image(state) unless state[:image_id]
        state[:container_id] = run_container(state) unless state[:container_id]
        state[:hostname] = 'localhost'
        if remote_socket?
          state[:hostname] = socket_uri.host
        elsif config[:use_internal_docker_network]
          state[:hostname] = container_ip(state)
        end
        state[:port] = container_ssh_port(state)
        if config[:wait_for_sshd]
          instance.transport.connection(state) do |conn|
            conn.wait_until_ready
          end
        end
      end

      def destroy(state)
        begin
          ::Docker::Container.get(state[:container_id], {}, @docker_api).remove(:force => true)
        rescue ::Docker::Error::NotFoundError => ex
          info(ex.to_s)
        end if state[:container_id]

        begin
          ::Docker::Image.get(state[:image_id], {}, @docker_api).remove()
        rescue ::Docker::Error::NotFoundError => ex
          info(ex.to_s)
        end if config[:remove_images] && state[:image_id]
      end

      def remote_socket?
        config[:socket] ? socket_uri.scheme == 'tcp' : false
      end

      protected

      def socket_uri
        URI.parse(config[:socket])
      end

      def generate_keys
        MUTEX_FOR_SSH_KEYS.synchronize do
          if !File.exist?(config[:public_key]) || !File.exist?(config[:private_key])
            private_key = OpenSSL::PKey::RSA.new(2048)
            blobbed_key = Base64.encode64(private_key.to_blob).gsub("\n", '')
            public_key = "ssh-rsa #{blobbed_key} kitchen_docker_key"
            File.open(config[:private_key], 'w') do |file|
              file.write(private_key)
              file.chmod(0600)
            end
            File.open(config[:public_key], 'w') do |file|
              file.write(public_key)
              file.chmod(0600)
            end
          end
        end
      end

      def build_dockerfile
        from = "FROM #{config[:image]}"

        env_variables = ''
        if config[:http_proxy]
          env_variables << "ENV http_proxy #{config[:http_proxy]}\n"
          env_variables << "ENV HTTP_PROXY #{config[:http_proxy]}\n"
        end

        if config[:https_proxy]
          env_variables << "ENV https_proxy #{config[:https_proxy]}\n"
          env_variables << "ENV HTTPS_PROXY #{config[:https_proxy]}\n"
        end

        if config[:no_proxy]
          env_variables << "ENV no_proxy #{config[:no_proxy]}\n"
          env_variables << "ENV NO_PROXY #{config[:no_proxy]}\n"
        end

        platform = case config[:platform]
        when 'debian', 'ubuntu'
          disable_upstart = <<-eos
            RUN [ ! -f "/sbin/initctl" ] || dpkg-divert --local --rename --add /sbin/initctl && ln -sf /bin/true /sbin/initctl
          eos
          packages = <<-eos
            ENV DEBIAN_FRONTEND noninteractive
            ENV container docker
            RUN apt-get update
            RUN apt-get install -y sudo openssh-server curl lsb-release
          eos
          config[:disable_upstart] ? disable_upstart + packages : packages
        when 'rhel', 'centos', 'fedora', 'oraclelinux'
          <<-eos
            ENV container docker
            RUN yum clean all
            RUN yum install -y sudo openssh-server openssh-clients which curl
            RUN [ -f "/etc/ssh/ssh_host_rsa_key" ] || ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
            RUN [ -f "/etc/ssh/ssh_host_dsa_key" ] || ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key -N ''
          eos
        when 'opensuse', 'sles'
          <<-eos
            ENV container docker
            RUN zypper install -y sudo openssh which curl
            RUN [ -f "/etc/ssh/ssh_host_rsa_key" ] || ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
            RUN [ -f "/etc/ssh/ssh_host_dsa_key" ] || ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key -N ''
          eos
        when 'arch'
          # See https://bugs.archlinux.org/task/47052 for why we
          # blank out limits.conf.
          <<-eos
            RUN pacman --noconfirm -Sy archlinux-keyring
            RUN pacman-db-upgrade
            RUN pacman --noconfirm -Syu openssl openssh sudo curl
            RUN [ -f "/etc/ssh/ssh_host_rsa_key" ] || ssh-keygen -A -t rsa -f /etc/ssh/ssh_host_rsa_key
            RUN [ -f "/etc/ssh/ssh_host_dsa_key" ] || ssh-keygen -A -t dsa -f /etc/ssh/ssh_host_dsa_key
            RUN echo >/etc/security/limits.conf
          eos
        when 'gentoo'
          <<-eos
            RUN emerge --sync
            RUN emerge net-misc/openssh app-admin/sudo
            RUN [ -f "/etc/ssh/ssh_host_rsa_key" ] || ssh-keygen -A -t rsa -f /etc/ssh/ssh_host_rsa_key
            RUN [ -f "/etc/ssh/ssh_host_dsa_key" ] || ssh-keygen -A -t dsa -f /etc/ssh/ssh_host_dsa_key
          eos
        when 'gentoo-paludis'
          <<-eos
            RUN cave sync
            RUN cave resolve -zx net-misc/openssh app-admin/sudo
            RUN [ -f "/etc/ssh/ssh_host_rsa_key" ] || ssh-keygen -A -t rsa -f /etc/ssh/ssh_host_rsa_key
            RUN [ -f "/etc/ssh/ssh_host_dsa_key" ] || ssh-keygen -A -t dsa -f /etc/ssh/ssh_host_dsa_key
          eos
        else
          raise ActionFailed,
          "Unknown platform '#{config[:platform]}'"
        end

        username = config[:username]
        public_key = IO.read(config[:public_key]).strip
        homedir = username == 'root' ? '/root' : "/home/#{username}"

        base = <<-eos
          RUN if ! getent passwd #{username}; then \
                useradd -d #{homedir} -m -s /bin/bash -p '*' #{username}; \
              fi
          RUN echo "#{username} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
          RUN echo "Defaults !requiretty" >> /etc/sudoers
          RUN mkdir -p #{homedir}/.ssh
          RUN chown -R #{username} #{homedir}/.ssh
          RUN chmod 0700 #{homedir}/.ssh
          RUN touch #{homedir}/.ssh/authorized_keys
          RUN chown #{username} #{homedir}/.ssh/authorized_keys
          RUN chmod 0600 #{homedir}/.ssh/authorized_keys
          RUN mkdir -p /run/sshd
        eos
        custom = ''
        Array(config[:provision_command]).each do |cmd|
          custom << "RUN #{cmd}\n"
        end
        ssh_key = "RUN echo #{Shellwords.escape(public_key)} >> #{homedir}/.ssh/authorized_keys"
        # Empty string to ensure the file ends with a newline.
        [from, env_variables, platform, base, custom, ssh_key, ''].join("\n")
      end

      def dockerfile
        if config[:dockerfile]
          template = IO.read(File.expand_path(config[:dockerfile]))
          context = DockerERBContext.new(config.to_hash)
          ERB.new(template).result(context.get_binding)
        else
          build_dockerfile
        end
      end

      def build_image(state)
        #build_context = config[:build_context] ? '.' : '-'
        options = {
          :nocache => config[:use_cache]
        }
        options = options.merge(config[:build_options]) unless config[:build_options].nil?
        # https://github.com/swipely/docker-api/blob/fc7ad57f77d59036dba9598ed52772778dc198c6/lib/docker/image.rb#L289 build_from_dir
        ::Docker::Image.build(dockerfile, options) do |v|
          ::Docker::Util.fix_json(v).each { |log| info(log['stream'].strip) }
        end.id
      end

      def build_run_options
        options = {}
        options['name'] = config[:instance_name] if config[:instance_name]
        options['Hostname'] = config[:hostname] if config[:hostname]
        options['Env'] = []
        options['Env'] << "http_proxy=#{config[:http_proxy]}" if config[:http_proxy]
        options['Env'] << "https_proxy=#{config[:https_proxy]}" if config[:https_proxy]
        options['HostConfig'] = {}
        options['HostConfig']['PublishAllPorts'] = config[:publish_all]
        options['HostConfig']['Memory'] = config[:memory] if config[:memory]
        options['HostConfig']['CpuShares'] = config[:cpu] if config[:cpu]
        options['HostConfig']['Privileged'] = config[:privileged]
        options['HostConfig']['PortBindings'] = {}

        options['ExposedPorts'] = {}
        options['ExposedPorts']['22/tcp'] = {}
        options['HostConfig']['PortBindings']['22/tcp'] = [{}]
        # FIXME: add support for syntax porA:portB
        Array(config[:forward]).each do |port| 
          options['ExposedPorts']["#{port}/tcp"] = {}
          options['HostConfig']['PortBindings']["#{port}/tcp"] = [{}]
        end unless config[:forward].nil?

        options['HostConfig']['Dns'] = Array(config[:dns]) unless config[:dns].nil?
        options['HostConfig']['ExtraHosts'] = Array(config[:add_host]) unless config[:add_host].nil?
        options['HostConfig']['VolumesFrom'] = Array(config[:volumes_from]) unless config[:volumes_from].nil?
        Array(config[:volumes]).each {|volume| options['Volumes'][volume] = {} }
        options['HostConfig']['Links'] = Array(config[:links]) unless config[:links].nil?
        Array(config[:devices]).each {|device| options['HostConfig']['Devices'][volume] = { 'PathOnHost' => device, 'PathInContainer' => device, 'CgroupPermissions' => 'mrw'} }
        options['HostConfig']['CapAdd'] = Array(config[:cap_add]) unless config[:cap_add].nil?
        options['HostConfig']['CapDrop'] = Array(config[:cap_drop]) unless config[:cap_drop].nil?
        options['HostConfig']['SecurityOpt'] = Array(config[:security_opt]) unless config[:security_opt].nil?
        options = options.merge(config[:run_options]) unless config[:run_options].nil?
        options
      end

      def run_container(state)
        ::Docker::Image.get(state[:image_id]).run(
          config[:run_command],
          build_run_options
        ).id
      end

      def container_ssh_port(state)
        begin
          if config[:use_internal_docker_network]
            return 22
          end
          ::Docker::Container.get(state[:container_id], {}, @docker_api)
            .info['NetworkSettings']['Ports']['22/tcp'][0]['HostPort']
        rescue
          raise ActionFailed,
          'Docker reports container has no ssh port mapped'
        end
      end

      def container_ip(state)
        begin
          ::Docker::Container.get(state[:container_id], {}, @docker_api)
            .info['NetworkSettings']['IPAddress']
        rescue
          raise ActionFailed,
          'Error getting internal IP of Docker container'
        end
      end

      def dockerfile_path(file)
        config[:build_context] ? Pathname.new(file.path).relative_path_from(Pathname.pwd).to_s : file.path
      end
    end
  end
end
