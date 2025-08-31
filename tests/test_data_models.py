import base64
import logging

import pytest
from pymcp.data_model.response_models import Base64EncodedBinaryDataResponse
import hashlib
import secrets
import random

logger = logging.getLogger(__name__)


class TestDataModels:
    @pytest.mark.parametrize(
        "iteration", range(len(hashlib.algorithms_available))
    )  # Repeats the test for all choices of hash algorithms
    def test_base64_encoded_binary_data_response_randomised(self, iteration: int):
        binary_data = secrets.token_bytes(random.randint(128, 1024))
        base64_encoded_data = base64.b64encode(binary_data)
        hash_algorithm = list(hashlib.algorithms_available)[iteration]
        logger.info(f"Hash algorithm: {hash_algorithm}")
        hasher = hashlib.new(hash_algorithm)
        hasher.update(binary_data)
        # Make sure that for variable length hash algorithms, such as SHAKE128 and SHAKE256, we get a fixed length hash for testing
        hash_value = (
            hasher.hexdigest()
            if not hash_algorithm.startswith("shake")
            else hasher.hexdigest(Base64EncodedBinaryDataResponse.SHAKE_DIGEST_LENGTH)  # type: ignore[call-arg]
        )

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
