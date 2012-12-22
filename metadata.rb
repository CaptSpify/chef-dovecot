maintainer       "Kyel Woodard"
maintainer_email "CaptSpify@Yahoo.com"
license          "Apache 2.0"
description      "Installs/Configures Dovecot"
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
version          "0.1.0"

%w{ debian }.each do |os|
  supports os
end
