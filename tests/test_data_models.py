import base64
from pymcp.data_model.response_models import Base64EncodedBinaryDataResponse
import hashlib
import secrets
import random


class TestDataModels:
    def test_random_base64_encoded_binary_data_response(self):
        binary_data = secrets.token_bytes(random.randint(128, 1024))
        base64_encoded_data = base64.b64encode(binary_data)
        hash_algorithm = random.choice(list(hashlib.algorithms_available))
        hasher = hashlib.new(hash_algorithm)
        hasher.update(binary_data)
        hash_value = hasher.hexdigest()

        model_instance = Base64EncodedBinaryDataResponse(
            data=base64_encoded_data, hash=hash_value, hash_algorithm=hash_algorithm
        )
        assert model_instance.data == binary_data
        assert model_instance.data != base64_encoded_data
        assert model_instance.hash == hash_value
        assert model_instance.hash_algorithm == hash_algorithm

    def test_base64_encoded_binary_data_response(self):
        binary_data = b"Hello world, from PyMCP!"
        base64_encoded_data = base64.b64encode(binary_data)
        hash_algorithm = "sha3_512"
        hasher = hashlib.new(hash_algorithm)
        hasher.update(binary_data)
        hash_value = hasher.hexdigest()

        model_instance = Base64EncodedBinaryDataResponse(
            data=base64_encoded_data, hash=hash_value, hash_algorithm=hash_algorithm
        )
        assert model_instance.data == binary_data
        assert model_instance.data != base64_encoded_data
        assert model_instance.hash == hash_value
        assert model_instance.hash_algorithm == hash_algorithm
