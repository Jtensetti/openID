#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf '%s\n' 'Tjipp requires the configured writable EBS volume at /srv/tjipp.' >&2
    exit 1
}

[[ -f /etc/tjipp/data-volume-id ]] || fail
mapfile -t volume_ids < /etc/tjipp/data-volume-id
[[ ${#volume_ids[@]} -eq 1 && ${volume_ids[0]} =~ ^vol-[0-9a-f]{17}$ ]] || fail
volume_id=${volume_ids[0]}
mount=$(findmnt --noheadings --raw --output SOURCE,FSTYPE,OPTIONS --mountpoint /srv/tjipp) || fail
[[ $mount != *$'\n'* ]] || fail
read -r source filesystem options <<< "$mount"
[[ -b $source && $filesystem == ext4 && ,$options, == *,rw,* ]] || fail
serial=$(lsblk --noheadings --nodeps --raw --output SERIAL -- "$source") || fail
[[ $serial == "${volume_id//-/}" ]] || fail
