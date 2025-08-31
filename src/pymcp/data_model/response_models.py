from typing import ClassVar, List
from pydantic import Base64Bytes, BaseModel, Field, model_validator

import hashlib


class Base64EncodedBinaryDataResponse(BaseModel):
    """
    A base64 encoded binary data for MCP response along with its cryptographic hash.
    """

    AVAILABLE_HASH_ALGORITHMS: ClassVar[List[str]] = list(hashlib.algorithms_available)
    AVAILABLE_HASH_ALGORITHMS_STR: ClassVar[str] = ""
    if not AVAILABLE_HASH_ALGORITHMS:  # pragma: no cover
        pass
    elif len(AVAILABLE_HASH_ALGORITHMS) == 1:  # pragma: no cover
        AVAILABLE_HASH_ALGORITHMS_STR = AVAILABLE_HASH_ALGORITHMS[0]
    elif len(AVAILABLE_HASH_ALGORITHMS) == 2:  # pragma: no cover
        AVAILABLE_HASH_ALGORITHMS_STR = " and ".join(AVAILABLE_HASH_ALGORITHMS)
    else:
        AVAILABLE_HASH_ALGORITHMS_STR = (
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
        if (
            self.hash_algorithm
            not in Base64EncodedBinaryDataResponse.AVAILABLE_HASH_ALGORITHMS
        ):
            raise ValueError(
                f"Unsupported hash algorithm: {self.hash_algorithm}. Available algorithms: {Base64EncodedBinaryDataResponse.AVAILABLE_HASH_ALGORITHMS_STR}"
            )
        hasher = hashlib.new(self.hash_algorithm)
        hasher.update(self.data)
        computed_hash = (
            hasher.hexdigest()
            if not self.hash_algorithm.startswith("shake")
            # Make sure that for variable length hash algorithms, such as SHAKE128 and SHAKE256, we get a fixed length hash for testing
            else hasher.hexdigest(Base64EncodedBinaryDataResponse.SHAKE_DIGEST_LENGTH)  # type: ignore[call-arg]
        )
        if computed_hash != self.hash:
            raise ValueError(
                f"Hash mismatch: provided hash {self.hash} does not match computed hash {computed_hash}."
            )
        return self
