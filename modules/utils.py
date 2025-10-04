import hashlib
import logging
import re
import shutil
import time
import tomllib
import traceback
import uuid
from pathlib import Path

import requests
from pgpy import PGPKey, PGPSignature
from tqdm import tqdm

READ_CHUNK_SIZE = 524288


def logging_critical_exception(msg, *args, **kwargs):
    """
    Log a critical exception with traceback information.

    Args:
        msg (str): The error message to be logged.
        *args: Variable length argument list to be passed to the logging.critical method.
        **kwargs: Keyword arguments to be passed to the logging.critical method.
    """
    logging.critical(f"{msg}\n{traceback.format_exc()}", *args, **kwargs)


def parse_config(toml_file: Path) -> dict | None:
    """Parse a TOML configuration file and return a dictionary representation.

    Args:
        toml_file (Path): The path to the TOML configuration file.

    Returns:
        dict | None: The parsed configuration as a dictionary, or None if there was an error during parsing.
    """
    with open(toml_file, "rb") as f:
        toml_dict = tomllib.load(f)
    return parse_config_from_dict(toml_dict)


def parse_config_from_dict(input_dict: dict):
    """Recursively parse the nested config dictionary and return a new dictionary where the keys are the directory, unless they are a module's name.

    Args:
        input_dict (dict): The input dictionary to be parsed.

    Returns:
        dict: The parsed dictionary with modified keys.
    """
    new_dict = {}
    for key, value in input_dict.items():
        if isinstance(value, dict):
            if "enabled" in value and not value["enabled"]:
                logging.debug(f"Skipping disabled module {key}")
                del value
                continue
            if "directory" in value:
                logging.debug(f"Found directory {value['directory']}")
                new_key = value["directory"]
                del value["directory"]
            else:
                logging.debug(f"Found module {key}")
                new_key = key
            new_dict[new_key] = parse_config_from_dict(value)
        elif key == "enabled":
            continue
        else:
            logging.debug(f"Found key {key}")
            new_dict[key] = value
    return new_dict


def md5_hash_check(file: Path, hash: str) -> bool:
    """
    Calculate the MD5 hash of a given file and compare it with a provided hash value.

    Args:
        file (Path): The path to the file for which the hash is to be calculated.
        hash (str): The MD5 hash value to compare against the calculated hash.

    Returns:
        bool: True if the calculated MD5 hash matches the provided hash; otherwise, False.
    """
    with open(file, "rb") as f:
        file_hash = hashlib.md5()
        while chunk := f.read(READ_CHUNK_SIZE):
            file_hash.update(chunk)
    result = hash.lower() == file_hash.hexdigest()

    logging.debug(
        f"[md5_hash_check] {file.resolve()}: `{hash.lower()}` is {'' if result else 'not'} equal to file hash `{file_hash.hexdigest()}`"
    )
    return result


def sha1_hash_check(file: Path, hash: str) -> bool:
    """
    Calculate the SHA-1 hash of a given file and compare it with a provided hash value.

    Args:
        file (Path): The path to the file for which the hash is to be calculated.
        hash (str): The SHA-1 hash value to compare against the calculated hash.

    Returns:
        bool: True if the calculated SHA-1 hash matches the provided hash; otherwise, False.
    """
    with open(file, "rb") as f:
        file_hash = hashlib.sha1()
        while chunk := f.read(READ_CHUNK_SIZE):
            file_hash.update(chunk)
    result = hash.lower() == file_hash.hexdigest()

    logging.debug(
        f"[sha1_hash_check] {file.resolve()}: `{hash.lower()}` is {'' if result else 'not'} equal to file hash `{file_hash.hexdigest()}`"
    )
    return result


def sha256_hash_check(file: Path, hash: str) -> bool:
    """
    Calculate the SHA-256 hash of a given file and compare it with a provided hash value.

    Args:
        file (str): The path to the file for which the hash is to be calculated.
        hash (str): The SHA-256 hash value to compare against the calculated hash.

    Returns:
        bool: True if the calculated SHA-256 hash matches the provided hash; otherwise, False.
    """
    with open(file, "rb") as f:
        file_hash = hashlib.sha256()
        while chunk := f.read(READ_CHUNK_SIZE):
            file_hash.update(chunk)
    result = hash.lower() == file_hash.hexdigest()

    logging.debug(
        f"[sha256_hash_check] {file.resolve()}: `{hash.lower()}` is {'' if result else 'not'} equal to file hash `{file_hash.hexdigest()}`"
    )
    return result


def sha512_hash_check(file: Path, hash: str) -> bool:
    """
    Calculate the SHA-512 hash of a given file and compare it with a provided hash value.

    Args:
        file (Path): The path to the file for which the hash is to be calculated.
        hash (str): The SHA-512 hash value to compare against the calculated hash.

    Returns:
        bool: True if the calculated SHA-512 hash matches the provided hash; otherwise, False.
    """
    with open(file, "rb") as f:
        file_hash = hashlib.sha512()
        while chunk := f.read(READ_CHUNK_SIZE):
            file_hash.update(chunk)
    result = hash.lower() == file_hash.hexdigest()

    logging.debug(
        f"[sha512_hash_check] {file.resolve()}: `{hash.lower()}` is {'' if result else 'not'} equal to file hash `{file_hash.hexdigest()}`"
    )
    return result


def pgp_check(file_path: Path, signature: str | bytes, public_key: str | bytes) -> bool:
    """Verifies the signature of a file against a publick ey

    Args:
        file_path (Path): Path to the file to check
        signature (str | bytes): Signature
        public_key (str | bytes): Public Key

    Raises:
        ValueError: If the supplied public key is invalid
        ValueError: If the supplied signature is invalid

    Returns:
        bool: Weither the check was successful or not
    """
    pub_key = PGPKey.from_blob(public_key)
    sig = PGPSignature.from_blob(signature)

    if not pub_key:
        raise ValueError(f"Invalid pub_key: {public_key}")
    elif not sig:
        raise ValueError(f"Invalid signature: {signature}")

    # For some reason, from_blob can return either a tuple with either [ThingIwant, Literally Nothing] or directly ThingIWant
    if isinstance(pub_key, tuple):
        pub_key = pub_key[0]
    if isinstance(sig, tuple):
        sig = sig[0]

    with open(file_path, "rb") as f:
        file_content = f.read()

    result = bool(pub_key.verify(file_content, sig))

    logging.debug(
        f"[pgp_check] {file_path.resolve()}: Signature is {'' if result else 'not'} valid"
    )

    return result


def parse_hash(
    hashes: str, match_strings_in_line: list[str], hash_position_in_line: int
):
    """Parse a list of hashes and extract a specific hash based on matching strings.

    Args:
        hashes (str): A string containing a list of hashes.
        match_strings_in_line (list[str]): List of strings that must be present in the line to consider it.
        hash_position_in_line (int): The position of the desired hash in each line.

    Returns:
        The extracted hash value.
    """
    logging.debug(
        f"[parse_hash] Parsing hashes with match strings `{match_strings_in_line}` and hash position {hash_position_in_line} in those hashes:\n{hashes}"
    )
    hash = next(
        line.split()[hash_position_in_line]
        for line in hashes.strip().splitlines()
        if all(match in line for match in match_strings_in_line)
    )
    logging.debug(f"[parse_hash] Extracted hash: `{hash}`")
    return hash


def download_file(url: str, local_file: Path, progress_bar: bool = True, retries=0) -> None:
    """
    Download a file from a given URL and save it to the local file system.
    Retries only on HTTP 403 errors. Any other error aborts immediately.
    """

    part_file = local_file.with_suffix(".part")
    logging.debug(f"[download_file] Downloading {url} to {part_file.resolve()}")

    retries_str = str(retries).lower() if isinstance(retries, str) else retries
    if retries_str == "all":
        user_max_retries = float('inf')
    else:
        try:
            user_max_retries = int(retries)
        except Exception:
            user_max_retries = 0

    attempt = 0
    started = False
    while True:
        try:
            resume_byte_pos = part_file.stat().st_size if part_file.exists() else 0
            headers = {"Range": f"bytes={resume_byte_pos}-"} if resume_byte_pos > 0 else {}
            with requests.get(url, stream=True, headers=headers) as r:
                if r.status_code == 403:
                    attempt += 1
                    max_retries = 7 if not started else user_max_retries
                    logging.warning(f"HTTP 403 Forbidden (attempt {attempt}/{max_retries if max_retries != float('inf') else '∞'}): {url}")
                    if max_retries != float('inf') and attempt > max_retries:
                        logging.error(f"Exceeded maximum retries for {url} (HTTP 403)")
                        if part_file.exists():
                            part_file.unlink()
                        raise Exception(f"Exceeded maximum retries for {url} (HTTP 403)")
                    else:
                        time.sleep(1)
                        continue
                elif r.status_code != 200 and r.status_code != 206:
                    logging.error(f"Download failed with HTTP status {r.status_code} for {url}")
                    if part_file.exists():
                        part_file.unlink()
                    raise Exception(f"Download failed with HTTP status {r.status_code} for {url}")
                total_size = int(r.headers.get("content-length", 0)) + resume_byte_pos if "content-length" in r.headers else None
                mode = "ab" if resume_byte_pos > 0 else "wb"
                with open(part_file, mode) as f:
                    if progress_bar:
                        with tqdm(
                            total=total_size, initial=resume_byte_pos, unit="B", desc=part_file.name, unit_scale=True
                        ) as pbar:
                            for chunk in r.iter_content(chunk_size=1024):
                                if chunk:
                                    f.write(chunk)
                                    pbar.update(len(chunk))
                                    started = True
                    else:
                        before = part_file.stat().st_size if part_file.exists() else 0
                        shutil.copyfileobj(r.raw, f)
                        after = part_file.stat().st_size if part_file.exists() else 0
                        if after > before:
                            started = True
        except requests.exceptions.RequestException as e:
            # For all network errors except HTTP 403, just wait and retry forever
            logging.warning(f"Network error: {e}\nWaiting for connection to resume for {url}...")
            time.sleep(5)
            continue
        except KeyboardInterrupt:
            logging.info(f"Download of {url} to {part_file.resolve()} was cancelled")
            if part_file.exists():
                part_file.unlink()
            raise
        else:
            break
    # After successful download, rename the part file to the final file
    part_file.rename(local_file)
