#!/bin/bash
cat <<'EOF' >> /root/.bashrc
export TERM=linux
cd ${HOME}
source ${HOME}/enterprise_cloud_discovery/bin/activate
echo -e "Welcome to Enterprise Cloud Discovery Engine!\nYou are already in the Enterprise Cloud Discovery Engine virtual environment, so just type \`enterprise-cloud-discovery\` to run it!\n    (for example: \`enterprise-cloud-discovery -h\` to see the help documentation).\n\nHave fun!\n\n"
EOF
