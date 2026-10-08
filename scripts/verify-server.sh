#!/usr/bin/env bash
set -euo pipefail
printf 'CPU architecture: '; uname -m
printf 'KVM device: '; if [[ -e /dev/kvm ]]; then ls -l /dev/kvm; else echo 'NOT PRESENT'; fi
printf 'Virtualization flags: '; if grep -Eq '\b(svm|vmx)\b' /proc/cpuinfo; then echo 'PRESENT'; else echo 'NOT EXPOSED'; fi
printf 'Dagu service: '; systemctl is-active isolab-dagu.service || true
printf 'Dashboard listen: '; ss -lnt | grep ':8525' || true
printf 'Memory:'; free -h
printf 'Disk:'; df -h /srv/isolab
