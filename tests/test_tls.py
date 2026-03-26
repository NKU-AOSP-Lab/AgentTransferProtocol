import os
import ssl
import tempfile

import pytest

from atp.security.tls import TLSConfig


class TestTLSConfig:
    def test_generate_self_signed_cert_creates_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "cert.pem")
            key_path = os.path.join(tmpdir, "key.pem")

            TLSConfig.generate_self_signed_cert(cert_path, key_path, domain="localhost")

            assert os.path.exists(cert_path)
            assert os.path.exists(key_path)
            assert os.path.getsize(cert_path) > 0
            assert os.path.getsize(key_path) > 0

    def test_create_server_context_with_generated_cert(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "cert.pem")
            key_path = os.path.join(tmpdir, "key.pem")
            TLSConfig.generate_self_signed_cert(cert_path, key_path)

            ctx = TLSConfig.create_server_context(cert_path, key_path)
            assert isinstance(ctx, ssl.SSLContext)

    def test_create_client_context_verify_true(self):
        ctx = TLSConfig.create_client_context(verify=True)
        assert isinstance(ctx, ssl.SSLContext)

    def test_create_client_context_verify_false(self):
        ctx = TLSConfig.create_client_context(verify=False)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_minimum_tls_version_is_1_3(self):
        ctx = TLSConfig.create_client_context(verify=False)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3

    def test_server_context_minimum_tls_version(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "cert.pem")
            key_path = os.path.join(tmpdir, "key.pem")
            TLSConfig.generate_self_signed_cert(cert_path, key_path)

            ctx = TLSConfig.create_server_context(cert_path, key_path)
            assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
