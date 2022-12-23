import base64

import boto3
import consul
import hvac

from base import *
from utils import (BINARY_OUTPUT_FOLDER)


class AWSKMSClient:
    def __init__(self):
        self.url = os.environ.get('AWS_KMS_ADDRESS', 'http://localhost:8080')
        self.kms_client = boto3.client('kms', aws_access_key_id='', aws_secret_access_key='',
                                       region_name=os.environ.get('KMS_REGION', 'eu-west-2'), endpoint_url=self.url)
        # override request signer to skip boto3 looking for credentials in ~/.aws_credentials
        self.kms_client._request_signer.sign = (lambda *args, **kwargs: None)

    def get_kms_url(self):
        return self.url

    def create_key(self):
        response = self.kms_client.create_key(Description='AcraMasterKey KEK')
        return response['KeyMetadata']['Arn']

    def create_alias(self, keyId, alias_name):
        self.kms_client.create_alias(
            AliasName=alias_name,
            TargetKeyId=keyId
        )

    def list_aliases(self, keyId=None):
        args = {}
        if keyId is not None:
            args['KeyId'] = keyId
        return self.kms_client.list_aliases(**args)

    def delete_alias(self, alias_name):
        self.kms_client.delete_alias(
            AliasName=alias_name,
        )

    def close(self):
        self.kms_client.close()

    def disable_key(self, keyId):
        self.kms_client.disable_key(KeyId=keyId)

    def encrypt(self, keyId, data):
        response = self.kms_client.encrypt(
            KeyId=keyId,
            Plaintext=data,
        )
        return response

    def decrypt(self, keyId, ciphertextBlob):
        response = self.kms_client.decrypt(
            KeyId=keyId,
            CiphertextBlob=ciphertextBlob,
        )
        return response


class VaultClient:
    version_options = {
        'v1': dict(version=1),
        'v2': dict(version=2),
    }

    def __init__(self, verify=None):
        self.url = os.environ.get('VAULT_ADDRESS', 'http://localhost:8201')
        self.token = os.environ.get('VAULT_CLIENT_TOKEN', 'root_token')
        self.vault_client = hvac.Client(url=self.url, token=self.token, verify=verify)

    def get_vault_url(self):
        return self.url

    def get_vault_token(self):
        return self.token

    def enable_kv_secret_engine(self, mount_path=None):
        self.vault_client.sys.enable_secrets_engine(
            backend_type='kv',
            path=mount_path,
            options=self.version_options[VAULT_KV_ENGINE_VERSION],
        )
        time.sleep(2)

    def disable_kv_secret_engine(self, mount_path=None):
        self.vault_client.sys.disable_secrets_engine(path=mount_path)

    def put_master_key_by_version(self, path, version, mount_point=None):
        self.master_key = get_master_key()
        master_secret = {
            'acra_master_key': self.master_key
        }

        kv_secret_engine = None
        if version == "v1":
            kv_secret_engine = self.vault_client.secrets.kv.v1
        elif version == "v2":
            kv_secret_engine = self.vault_client.secrets.kv.v2

        kv_secret_engine.create_or_update_secret(
            path=path,
            secret=master_secret,
            mount_point=mount_point,
        )

    def get_vault_cli_args(self, mount_path=None, secret_path=None, keystore_encryption_type='vault_master_key'):
        args = {
            'vault_connection_api_string': self.vault_client.url,
            'vault_secrets_path': '{0}/{1}'.format(mount_path, secret_path),
            'keystore_encryption_type': keystore_encryption_type
        }

        if TEST_SSL_VAULT:
            args['vault_tls_transport_enable'] = True
            args['vault_tls_client_ca'] = TEST_VAULT_TLS_CA
        return args


class ConsulClient:
    def __init__(self, url, verify=True, cert=None):
        self.url = urlparse(url)
        self.client = consul.Consul(port=self.url.port, scheme=self.url.scheme, host=self.url.hostname, cert=cert,
                                    verify=verify)

    def get_consul_url(self):
        return self.url.geturl()

    def set(self, key, value):
        self.client.kv.put(key, value)


class HashiCorpVaultMasterKeyLoaderMixin:
    DEFAULT_MOUNT_PATH = 'test_kv'
    secret_path = 'foo'

    def setUp(self):
        if not TEST_WITH_VAULT:
            self.skipTest("test with HashiCorp Vault ACRA_MASTER_KEY loader")

        if TEST_SSL_VAULT:
            self.vault_client = VaultClient(verify=TEST_VAULT_TLS_CA)
        else:
            self.vault_client = VaultClient()

        self.vault_client.enable_kv_secret_engine(mount_path=self.DEFAULT_MOUNT_PATH)
        self.vault_client.put_master_key_by_version(self.secret_path, VAULT_KV_ENGINE_VERSION,
                                                    mount_point=self.DEFAULT_MOUNT_PATH)
        super().setUp()

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        args = self.vault_client.get_vault_cli_args(self.DEFAULT_MOUNT_PATH, self.secret_path)
        acra_kwargs.update(args)
        return self._fork_acra(acra_kwargs, popen_kwargs)

    def fork_translator(self, translator_kwargs, popen_kwargs=None):
        args = self.vault_client.get_vault_cli_args(self.DEFAULT_MOUNT_PATH, self.secret_path)
        translator_kwargs.update(args)
        return super().fork_translator(translator_kwargs, popen_kwargs)

    def read_rotation_public_key(self, extra_kwargs: dict = None):
        args = self.vault_client.get_vault_cli_args(self.DEFAULT_MOUNT_PATH, self.secret_path,
                                                    keystore_encryption_type='env_master_key')
        return super().read_rotation_public_key(extra_kwargs=args)

    def create_keypair(self, extra_kwargs: dict = None):
        args = self.vault_client.get_vault_cli_args(self.DEFAULT_MOUNT_PATH, self.secret_path,
                                                    keystore_encryption_type='env_master_key')
        return super().create_keypair(extra_kwargs=args)

    def tearDown(self):
        super().tearDown()
        self.vault_client.disable_kv_secret_engine(mount_path=self.DEFAULT_MOUNT_PATH)


class KMSAWSType:
    def setUp(self):
        if not TEST_WITH_AWS_KMS:
            self.skipTest("test with AWS KMS ACRA_MASTER_KEY loader")

        configuration = {
            'access_key_id': 'access_key_id',
            'secret_access_key': 'secret_key_id',
            'region': os.environ.get('KMS_REGION', 'eu-west-2'),
            'endpoint': os.environ.get('AWS_KMS_ADDRESS', 'http://localhost:8080')
        }
        self.config_file = tempfile.NamedTemporaryFile('w+', encoding='utf-8')
        json.dump(configuration, self.config_file)
        self.config_file.flush()
        super().setUp()

    def get_kms_type(self):
        return 'aws'

    def get_kms_configuration_path(self):
        return self.config_file.name


class KMSPerClientEncryptorMixin:
    poison_record = None

    def setUp(self):
        self.keys_dir = tempfile.TemporaryDirectory().name

        extra_args = {
            'kms_type': self.get_kms_type(),
            'kms_credentials_path': self.get_kms_configuration_path(),
            'keystore_encryption_type': "kms_per_client",
        }
        assert create_client_keypair_from_certificate(TEST_TLS_CLIENT_CERT, keys_dir=self.keys_dir,
                                                      extra_kwargs=extra_args) == 0
        assert create_client_keypair_from_certificate(TEST_TLS_CLIENT_2_CERT, keys_dir=self.keys_dir,
                                                      extra_kwargs=extra_args) == 0

        self.poison_record = get_new_poison_record(extra_kwargs=extra_args, keys_dir=self.keys_dir)
        super().setUp()

    def get_poison_records(self):
        return self.poison_record

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        acra_kwargs['kms_type'] = self.get_kms_type()
        acra_kwargs['kms_credentials_path'] = self.get_kms_configuration_path()
        acra_kwargs['keystore_encryption_type'] = 'kms_per_client'
        acra_kwargs['keys_dir'] = self.keys_dir

        return super(KMSPerClientEncryptorMixin, self).fork_acra(popen_kwargs, **acra_kwargs)

    def fork_translator(self, translator_kwargs, popen_kwargs=None):
        args = {
            'kms_type': self.get_kms_type(),
            'kms_credentials_path': self.get_kms_configuration_path(),
            'keystore_encryption_type': 'kms_per_client',
            'keys_dir': self.keys_dir,
            'logging_format': 'text',
        }
        translator_kwargs.update(args)
        return super(KMSPerClientEncryptorMixin, self).fork_translator(translator_kwargs, popen_kwargs)


class HashicorpConsulEncryptorConfigLoaderMixin:
    ENCRYPTOR_CONFIG_KEY_PATH = 'acra/encryptor_config'

    def setUp(self):
        if not TEST_CONSUL_ENCRYPTOR_CONFIG:
            self.skipTest("test with HashiCorp Consul EncryptorConfig loader")

        if TEST_SSL_CONSUL:
            self.consul_client = ConsulClient(url=os.environ.get('CONSUL_ADDRESS', 'https://localhost:8501'),
                                              verify=TEST_CONSUL_TLS_CA,
                                              cert=(TEST_TLS_CLIENT_CERT, TEST_TLS_CLIENT_KEY))
        else:
            self.consul_client = ConsulClient(url=os.environ.get('CONSUL_ADDRESS', 'http://localhost:8500'))

        encryptor_config = self.prepare_config()
        self.consul_client.set(self.ENCRYPTOR_CONFIG_KEY_PATH, encryptor_config)
        super().setUp()

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        args = {
            'consul_connection_api_string': self.consul_client.get_consul_url(),
            'consul_kv_config_path': self.ENCRYPTOR_CONFIG_KEY_PATH,
            'encryptor_config_storage_type': 'consul'
        }
        if TEST_SSL_CONSUL:
            args['consul_tls_enable'] = True
            args['consul_tls_client_ca'] = TEST_CONSUL_TLS_CA
            args['consul_tls_client_cert'] = TEST_TLS_CLIENT_CERT
            args['consul_tls_client_key'] = TEST_TLS_CLIENT_KEY
            args['consul_tls_client_auth'] = 4

        acra_kwargs.update(args)
        return super(HashicorpConsulEncryptorConfigLoaderMixin, self).fork_acra(popen_kwargs, **acra_kwargs)

    def prepare_config(self):
        with open(self.get_encryptor_config_path(), 'rb') as config_file:
            return base64.b64encode(config_file.read())


class AWSKMSMasterKeyLoaderMixin:
    def setUp(self):
        if not TEST_WITH_AWS_KMS:
            self.skipTest("test with AWS KMS ACRA_MASTER_KEY loader")

        self.kms_client = AWSKMSClient()
        self.master_key_kek_uri = self.kms_client.create_key()
        self.kms_client.create_alias(keyId=self.master_key_kek_uri, alias_name='alias/acra_master_key')

        master_key = b64decode(get_master_key())
        response = self.kms_client.encrypt(keyId=self.master_key_kek_uri, data=master_key)

        self.master_key_ciphertext = b64encode(response['CiphertextBlob']).decode("utf-8")
        self.create_configuration_file()

        super().setUp()

    def create_configuration_file(self):
        configuration = {
            'access_key_id': 'access_key_id',
            'secret_access_key': 'secret_key_id',
            'region': os.environ.get('KMS_REGION', 'eu-west-2'),
            'endpoint': self.kms_client.get_kms_url()
        }
        self.config_file = tempfile.NamedTemporaryFile('w+', encoding='utf-8')
        json.dump(configuration, self.config_file)
        self.config_file.flush()

    def fork_acra(self, popen_kwargs: dict = None, **acra_kwargs: dict):
        args = {
            'kms_credentials_path': self.config_file.name,
            'kms_type': 'aws',
            'keystore_encryption_type': 'kms_encrypted_master_key'
        }
        os.environ[ACRA_MASTER_KEY_VAR_NAME] = self.master_key_ciphertext
        acra_kwargs.update(args)
        return super(AWSKMSMasterKeyLoaderMixin, self).fork_acra(popen_kwargs, **acra_kwargs)

    def fork_translator(self, translator_kwargs, popen_kwargs=None):
        args = {
            'kms_credentials_path': self.config_file,
            'kms_type': 'aws',
            'keystore_encryption_type': 'kms_encrypted_master_key'
        }
        os.environ[ACRA_MASTER_KEY_VAR_NAME] = self.master_key_ciphertext
        translator_kwargs.update(args)
        return super(AWSKMSMasterKeyLoaderMixin, self).fork_translator(translator_kwargs, popen_kwargs)

    def tearDown(self):
        super().tearDown()
        self.kms_client.delete_alias(alias_name='alias/acra_master_key')
        self.kms_client.disable_key(keyId=self.master_key_kek_uri)
        self.kms_client.close()
        os.environ[ACRA_MASTER_KEY_VAR_NAME] = get_master_key()


class KeyMakerTestWithAWSKMS(unittest.TestCase):
    def setUp(self):
        if not TEST_WITH_AWS_KMS:
            self.skipTest("test with AWS KMS ACRA_MASTER_KEY loader")

        self.kms_client = AWSKMSClient()
        self.create_configuration_file()

    def create_configuration_file(self):
        configuration = {
            'access_key_id': 'access_key_id',
            'secret_access_key': 'secret_key_id',
            'region': os.environ.get('KMS_REGION', 'eu-west-2'),
            'endpoint': os.environ.get('AWS_KMS_ADDRESS', 'http://localhost:8080')
        }
        self.config_file = tempfile.NamedTemporaryFile('w+', encoding='utf-8')
        json.dump(configuration, self.config_file)
        self.config_file.flush()

    def test_generate_master_key_with_kms_create(self):
        master_key_file = tempfile.NamedTemporaryFile('w+', encoding='utf-8')
        subprocess.check_output(
            [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'), '--keystore={}'.format(KEYSTORE_VERSION),
             '--generate_master_key={}'.format(master_key_file.name),
             '--kms_type=aws',
             '--keystore_encryption_type=kms_encrypted_master_key',
             '--kms_credentials_path={}'.format(self.config_file.name)])

        resp = self.kms_client.list_aliases()
        created_arn = resp['Aliases'][0]['AliasArn']

        ciphertext = open(master_key_file.name, "rb").read()
        decrypt_resp = self.kms_client.decrypt(keyId=created_arn, ciphertextBlob=ciphertext)
        self.assertEqual(len(decrypt_resp['Plaintext']), 32)
        self.assertNotEqual(decrypt_resp['Plaintext'], ciphertext)

        # should exit 1 for next create as key already exist on KMS
        with tempfile.NamedTemporaryFile('w+', encoding='utf-8') as master_key_file:
            try:
                subprocess.check_output(
                    [os.path.join(BINARY_OUTPUT_FOLDER, 'acra-keymaker'), '--keystore={}'.format(KEYSTORE_VERSION),
                     '--generate_master_key={}'.format(master_key_file.name),
                     '--kms_type=aws',
                     '--keystore_encryption_type=kms_encrypted_master_key',
                     '--kms_credentials_path={}'.format(self.config_file.name)], stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as exp:
                self.assertIn("alias/acra_master_key already exists", str(exp.output))

    def tearDown(self):
        self.kms_client.delete_alias(alias_name='alias/acra_master_key')


class TestEnableCachedOnStartupAWSKMSKeystore(KMSAWSType, KMSPerClientEncryptorMixin, TestEnableCachedOnStartupTest):
    # just passed test to check if cache on start is working with KMS
    def testReadAcrastructInAcrastruct(self):
        pass

    def testClientIDRead(self):
        pass


# class TestPoisonRecordShutdownWithAWSKMSKeystore(KMSAWSType, KMSPerClientEncryptorMixin, TestPoisonRecordShutdown):
#     def get_poison_record_data(self):
#         return self.get_poison_records()


class AcraTranslatorTestWithAWSKMS(AWSKMSMasterKeyLoaderMixin, AcraTranslatorTest):
    # ignore test as test logic contains some internal keys generation with ENV MasterKey loading
    def testGRPCApi(self):
        pass

    def testHTTPApi(self):
        pass


class TestTranslatorDisableCachedOnStartupWithAWSKMS(AWSKMSMasterKeyLoaderMixin, TestTranslatorDisableCachedOnStartup):
    pass


class TestTranslatorDisableCachedOnStartupWithAWSKMSKeystore(KMSAWSType, KMSPerClientEncryptorMixin,
                                                             TestTranslatorDisableCachedOnStartup):
    pass


class TestAcraTranslatorWithVaultMasterKeyLoaderByDistinguishedName(HashiCorpVaultMasterKeyLoaderMixin,
                                                                    TLSAuthenticationByDistinguishedNameMixin,
                                                                    AcraTranslatorTest):
    pass


class TestAcraTranslatorWithVaultMasterKeyLoaderBySerialNumber(HashiCorpVaultMasterKeyLoaderMixin,
                                                               TLSAuthenticationBySerialNumberMixin,
                                                               AcraTranslatorTest):
    pass


class TestAcraTranslatorClientIDFromTLSByDistinguishedNameVaultMasterKeyLoader(HashiCorpVaultMasterKeyLoaderMixin,
                                                                               TestAcraTranslatorClientIDFromTLSByDistinguishedName):
    pass


class TestKeyRotationWithVaultMasterKeyLoader(HashiCorpVaultMasterKeyLoaderMixin, TestKeyRotation):
    pass


class TestAcraTranslatorClientIDFromTLSBySerialNumberVaultMasterKeyLoader(HashiCorpVaultMasterKeyLoaderMixin,
                                                                          TLSAuthenticationBySerialNumberMixin,
                                                                          TestAcraTranslatorClientIDFromTLSByDistinguishedName):
    pass
