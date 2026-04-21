"""Centralized test settings shared across test modules."""

import os

TEST_ROOT = "/tmp/xrd-test"
PKI_DIR = os.path.join(TEST_ROOT, "pki")
DATA_ROOT = os.path.join(TEST_ROOT, "data")
TOKENS_DIR = os.path.join(TEST_ROOT, "tokens")

NGINX_BIN = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
XROOTD_BIN = os.environ.get("TEST_XROOTD_BIN", "xrootd")
XRDFS_BIN = os.environ.get("TEST_XRDFS_BIN", "xrdfs")
XRDCP_BIN = os.environ.get("TEST_XRDCP_BIN", "xrdcp")

CA_DIR = os.path.join(PKI_DIR, "ca")
CA_CERT = os.path.join(CA_DIR, "ca.pem")
CA_KEY = os.path.join(CA_DIR, "ca.key")

USER_CERT = os.path.join(PKI_DIR, "user", "usercert.pem")
USER_KEY = os.path.join(PKI_DIR, "user", "userkey.pem")
PROXY_STD = os.path.join(PKI_DIR, "user", "proxy_std.pem")
PROXY_CMS = os.path.join(PKI_DIR, "user", "proxy_cms.pem")
PROXY_ATLAS = os.path.join(PKI_DIR, "user", "proxy_atlas.pem")

SERVER_CERT = os.path.join(PKI_DIR, "server", "hostcert.pem")
SERVER_KEY = os.path.join(PKI_DIR, "server", "hostkey.pem")

VOMSDIR = os.path.join(PKI_DIR, "vomsdir")
VOMS_CERT = os.path.join(PKI_DIR, "voms", "vomscert.pem")
VOMS_KEY = os.path.join(PKI_DIR, "voms", "vomskey.pem")
