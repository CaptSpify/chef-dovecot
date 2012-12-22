#
# Cookbook Name:: dovecot
# Recipe:: default
#
# Copyright 2012, Kyel Woodard
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

package "dovecot" do
	case node[:platform]
	when "ubuntu","debian","redhat","fedora","suse"
    then
		package_name "dovecot-common"
	end
	action :install
end

directory "/var/log/dovecot/" do
  owner node[:dovecot][:user]
  group node[:dovecot][:user]
  mode 0755
end

service "dovecot" do
	case node[:platform]
	when "debian","ubuntu","centos", "redhat"
    then
		service_name "dovecot"
	end
	supports :status => true, :reload => true, :restart => true
	action [ :enable ]
end

template "#{node[:dovecot][:config_path]}/#{node[:dovecot][:config]}" do
	source "dovecot.conf.erb"
	owner "root"
	group "root"
	mode 0644
    variables :protocol_examples => node['dovecot']['protocols_example']
  notifies :restart, resources(:service => "dovecot")
end

template "#{node[:dovecot][:config_path]}/#{node[:dovecot][:db_example_config]}" do
	source "dovecot-db-example.conf.erb"
	owner "root"
	group "root"
	mode 0644
  notifies :restart, resources(:service => "dovecot")
end

template "#{node[:dovecot][:config_path]}/#{node[:dovecot][:dict_sql_example_config]}" do
	source "dovecot-dict-sql-example.conf.erb"
	owner "root"
	group "root"
	mode 0644
  notifies :restart, resources(:service => "dovecot")
end

template "#{node[:dovecot][:config_path]}/#{node[:dovecot][:ldap_config]}" do
	source "dovecot-ldap.conf.erb"
	owner "root"
	group "root"
	mode 0644
  notifies :restart, resources(:service => "dovecot")
end

template "#{node[:dovecot][:config_path]}/#{node[:dovecot][:sql_config]}" do
	source "dovecot-sql.conf.erb"
	owner "root"
	group "root"
	mode 0644
  notifies :restart, resources(:service => "dovecot")
end

service "dovecot" do
	action [ :restart ]
end
