from functools import cache
from pathlib import Path

import requests
from bs4 import BeautifulSoup, Tag

from modules.exceptions import IntegrityCheckError, VersionNotFoundError
from modules.updaters.GenericUpdater import GenericUpdater
from modules.utils import parse_hash, sha256_hash_check

DOMAIN = "https://clonezilla.org"
FILE_NAME = "clonezilla-live-[[VER]]-amd64.iso"


class Clonezilla(GenericUpdater):
    """
    A class representing an updater for Clonezilla.

    Note:
        This class inherits from the abstract base class GenericUpdater.
    """

    def __init__(self, folder_path: Path) -> None:
        file_path = folder_path / FILE_NAME
        super().__init__(file_path)

    @cache
    def _get_download_link(self) -> str:
        ver = self._version_to_str(self._get_latest_version())
        repo = "https://downloads.sourceforge.net"
        return f"{repo}/clonezilla/clonezilla-live-{Clonezilla._get_clonezilla_version_style(ver)}-amd64.iso"

    def check_integrity(self) -> bool:
        from modules.utils_network import robust_get
        from modules.utils_network_patch import get_cli_retries
        resp = robust_get(f"{DOMAIN}/downloads/stable/checksums-contents.php", retries=get_cli_retries(), delay=1)
        if resp is None:
            print("Clonezilla.py HAD 403 ERROR AND CANNOT BE DOWNLOADED")
            return
        soup = BeautifulSoup(resp.content, features="html.parser")
        pre: Tag | None = soup.find("pre")  # type: ignore
        if not pre:
            raise IntegrityCheckError(
                "Unable to extract `<pre>` elements from checksum"
            )

        checksums: list[str] = pre.text.split("###")
        for checksum in checksums:
            if "SHA256" in checksum:
                sha256_sums = checksum
                break
        else:
            raise IntegrityCheckError("Could not find SHA256 sum")

        sha256_hash = parse_hash(sha256_sums, ["amd64.iso"], 0)

        return sha256_hash_check(
            self._get_complete_normalized_file_path(absolute=True), sha256_hash
        )

    @cache
    def _get_latest_version(self) -> list[str]:
        from modules.utils_network import robust_get
        from modules.utils_network_patch import get_cli_retries
        resp = robust_get(f"{DOMAIN}/downloads/stable/changelog-contents.php", retries=get_cli_retries(), delay=1)
        if resp is None:
            raise ConnectionError(f"Failed to fetch changelog-contents.php from '{DOMAIN}'")
        soup = BeautifulSoup(resp.content, features="html.parser")
        first_paragraph: Tag | None = soup.find("p")  # type: ignore
        if not first_paragraph:
            raise VersionNotFoundError(
                "Unable to extract `<p>` elements from changelog"
            )
        version_raw = first_paragraph.getText().split()[-1]
        # Only keep numeric and dot components for version comparison
        version_clean = version_raw.replace("-", ".")
        version_parts = [part for part in version_clean.split(".") if part.isdigit()]
        return version_parts

    @cache
    @staticmethod
    def _get_clonezilla_version_style(version: str):
        """
        Convert the version string from "x.y.z" to "x.y-z" format, as used by Clonezilla.

        Parameters:
            version (str): The version string in "x.y.z.a" format.

        Returns:
            str: The version string in "x.y.z-a" format.
        """
        return "-".join(version.rsplit(".", 1))
