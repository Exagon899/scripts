"""Cloud / CLI / dev-tool credential stores in user homes. These are flat
credential files that almost always sit in cleartext (or trivially reversible),
and are the pivot into AWS/Azure/GCP/K8s/registries."""
from __future__ import annotations

import os
from typing import List

from core.secret import Secret, Status
from core.tools import read_text, home_dirs, user_of_home, exists, isdir
from .base import BaseCollector

# (relative path under home, type, note). Cleartext text files get dumped;
# binary/complex stores just get flagged with their path.
TEXT_FILES = [
    (".aws/credentials", "aws", "AWS access keys"),
    (".aws/config", "aws", "AWS profiles/roles"),
    (".azure/accessTokens.json", "azure", "Azure access tokens"),
    (".azure/azureProfile.json", "azure", "Azure account profile"),
    (".config/gcloud/application_default_credentials.json", "gcp", "GCP ADC"),
    (".config/gcloud/legacy_credentials", "gcp", "GCP legacy creds dir"),
    (".kube/config", "k8s", "Kubernetes contexts/tokens/certs"),
    (".docker/config.json", "docker", "Docker registry auth (base64)"),
    (".git-credentials", "git", "Git stored creds (user:pass@host)"),
    (".netrc", "netrc", "netrc machine/login/password"),
    (".pypirc", "pypi", "PyPI upload creds"),
    (".npmrc", "npm", "npm registry _auth/_password"),
    (".s3cfg", "s3", "s3cmd access/secret key"),
    (".config/rclone/rclone.conf", "rclone", "rclone remote tokens/pw"),
    (".config/filezilla/sitemanager.xml", "filezilla", "FileZilla saved sites (base64)"),
    (".subversion/auth", "svn", "SVN cached auth dir"),
    (".config/gh/hosts.yml", "gh", "GitHub CLI oauth token"),
    (".terraform.d/credentials.tfrc.json", "terraform", "Terraform Cloud token"),
]

BINARY_FLAG = [
    (".config/gcloud/credentials.db", "gcp", "GCP CLI creds DB - pull & read sqlite"),
    (".local/share/keyrings", "keyring", "GNOME keyring - needs login pw to decrypt"),
]


class CloudCollector(BaseCollector):
    name = "Cloud"
    description = "aws/azure/gcp/k8s/docker/git/netrc/registry credential files"

    def collect(self) -> List[Secret]:
        found: List[Secret] = []
        for h in home_dirs():
            user = user_of_home(h)
            for rel, typ, note in TEXT_FILES:
                p = os.path.join(h, rel)
                if isdir(p):
                    found.append(Secret("Cloud", user, p, Status.INFO,
                                        target=p, secret_type=typ,
                                        notes=note + " (dir - review)"))
                    continue
                txt = read_text(p, max_bytes=128 * 1024)
                if not txt or not txt.strip():
                    continue
                # dump the whole small cred file content, trimmed, as cleartext
                snippet = txt.strip()
                found.append(Secret("Cloud", user, snippet[:300], Status.CLEARTEXT,
                                    target=p, secret_type=typ, notes=note))
            for rel, typ, note in BINARY_FLAG:
                p = os.path.join(h, rel)
                if exists(p):
                    found.append(Secret("Cloud", user, p, Status.INFO,
                                        target=p, secret_type=typ, notes=note))
        return found
