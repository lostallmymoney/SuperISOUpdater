from functools import cache
from pathlib import Path

import requests
from bs4 import BeautifulSoup

from modules.updaters.GenericUpdater import GenericUpdater
from modules.utils import sha256_hash_check

DOMAIN = "https://www.truenas.com"
DOWNLOAD_PAGE_URL = f"{DOMAIN}/download-truenas-[[EDITION]]"
FILE_NAME = "TrueNAS-[[EDITION]]-[[VER]].iso"


class TrueNAS(GenericUpdater):
    """
    A class representing an updater for TrueNAS.

    Attributes:
        valid_editions (list[str]): List of valid editions to use
        edition (str): Edition to download
        download_page (requests.Response): The HTTP response containing the download page HTML.
        soup_download_page (BeautifulSoup): The parsed HTML content of the download page.

    Note:
        This class inherits from the abstract base class GenericUpdater.
    """

    def __init__(self, folder_path: Path, edition: str) -> None:
        self.valid_editions = ["core", "scale"]
        self.edition = edition.lower()

        file_path = folder_path / FILE_NAME
        super().__init__(file_path)


        self.download_page_url = DOWNLOAD_PAGE_URL.replace("[[EDITION]]", self.edition)
        from modules.utils_network import robust_get
        from modules.utils_network_patch import get_cli_retries
        self.download_page = robust_get(self.download_page_url, retries=get_cli_retries(), delay=1)
        if self.download_page is None:
            print("TrueNAS.py HAD 403 ERROR AND CANNOT BE DOWNLOADED")
            return
        self.soup_download_page = BeautifulSoup(
            self.download_page.content, features="html.parser"
        )

    @cache
    def _get_download_link(self) -> str:
        a_tag = self.soup_download_page.find("a", attrs={"id": "downloadTrueNAS"})

        if not a_tag:
            raise LookupError("Could not find HTML tag containing download URL")

        return a_tag["href"]  # type: ignore

    def check_integrity(self) -> bool:
        sha256_url = f"{self._get_download_link()}.sha256"
        from modules.utils_network import robust_get
        from modules.utils_network_patch import get_cli_retries
        resp = robust_get(sha256_url, retries=get_cli_retries(), delay=1)
        if resp is None:
            raise ConnectionError(f"Failed to fetch sha256 from '{sha256_url}'")
        sha256_sums = resp.text.split()
        # for some reason TrueNAS has two different formats for their sha256 file
        if sha256_sums[0] == "SHA256":
            sha256_sum = sha256_sums[-1]
        else:
            sha256_sum = sha256_sums[0]
        return sha256_hash_check(
            self._get_complete_normalized_file_path(absolute=True),
            sha256_sum,
        )

    @cache
    def _get_latest_version(self) -> list[str]:
        download_link = self._get_download_link()
        version = download_link.split("-")[-1]

        return self._str_to_version(version.replace(".iso", ""))
