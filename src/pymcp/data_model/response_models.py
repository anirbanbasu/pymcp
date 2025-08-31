from typing import ClassVar, List
from pydantic import Base64Bytes, BaseModel, Field, model_validator

import hashlib


class Base64EncodedBinaryDataResponse(BaseModel):
    """
    A base64 encoded binary data for MCP response along with its cryptographic hash.
    """

    AVAILABLE_HASH_ALGORITHMS: ClassVar[List[str]] = list(hashlib.algorithms_available)
    AVAILABLE_HASH_ALGORITHMS_STR: ClassVar[str] = (
        ", ".join(AVAILABLE_HASH_ALGORITHMS[:-1])
        + f", and {AVAILABLE_HASH_ALGORITHMS[-1]}"
    )
    # See https://docs.python.org/3/library/hashlib.html#shake-variable-length-digests
    SHAKE_DIGEST_LENGTH: ClassVar[int] = 32  # bytes

    data: Base64Bytes = Field(
        description="Base64 encoded binary data.",
    )
    hash: str = Field(
        description="A hexadecimal encoded of a hash of the binary data.",
    )
    hash_algorithm: str = Field(
        description=f"The algorithm used to compute the hash, e.g., 'sha3_512'. Available algorithms: {AVAILABLE_HASH_ALGORITHMS_STR}",
    )

    @model_validator(mode="after")
    def check_data_hash(self) -> "Base64EncodedBinaryDataResponse":
        assert (
            self.hash_algorithm
            in Base64EncodedBinaryDataResponse.AVAILABLE_HASH_ALGORITHMS
        ), (
            f"Unsupported hash algorithm: {self.hash_algorithm}. Available algorithms: {Base64EncodedBinaryDataResponse.AVAILABLE_HASH_ALGORITHMS_STR}"
        )
        hasher = hashlib.new(self.hash_algorithm)
        hasher.update(self.data)
        # Make sure that for variable length hash algorithms, such as SHAKE128 and SHAKE256, we get a fixed length hash for testing
        computed_hash = (
            hasher.hexdigest()
            if not self.hash_algorithm.startswith("shake")
            else hasher.hexdigest(Base64EncodedBinaryDataResponse.SHAKE_DIGEST_LENGTH)  # type: ignore[call-arg]
        )
        assert computed_hash == self.hash, (
            f"Hash mismatch: expected {self.hash}, got {computed_hash}"
        )
        return self
