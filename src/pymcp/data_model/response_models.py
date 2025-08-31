from pydantic import Base64Bytes, BaseModel, Field, model_validator

import hashlib


class Base64EncodedBinaryDataResponse(BaseModel):
    """
    A base64 encoded binary data for MCP response along with its cryptographic hash.
    """

    data: Base64Bytes = Field(
        description="Base64 encoded binary data.",
    )
    hash: str = Field(
        description="A hexadecimal encoded of a hash of the binary data.",
    )
    hash_algorithm: str = Field(
        description=f"The algorithm used to compute the hash, e.g., 'sha3_512'. Available algorithms: {', '.join(list(hashlib.algorithms_available)[:-1])}, and {list(hashlib.algorithms_available)[-1]}",
    )

    @model_validator(mode="after")
    def check_data_hash(self) -> "Base64EncodedBinaryDataResponse":
        list_of_hash_algorithms = list(hashlib.algorithms_available)
        assert self.hash_algorithm in list_of_hash_algorithms, (
            f"Unsupported hash algorithm: {self.hash_algorithm}. Available algorithms: {', '.join(list_of_hash_algorithms[:-1])}, and {list_of_hash_algorithms[-1]}"
        )
        hasher = hashlib.new(self.hash_algorithm)
        hasher.update(self.data)
        # Make sure that for variable length hash algorithms, such as SHAKE128 and SHAKE256, we get a fixed length hash for testing
        computed_hash = (
            hasher.hexdigest()
            if not self.hash_algorithm.startswith("shake")
            else hasher.hexdigest(32)  # type: ignore[call-arg]
        )
        assert computed_hash == self.hash, (
            f"Hash mismatch: expected {self.hash}, got {computed_hash}"
        )
        return self
