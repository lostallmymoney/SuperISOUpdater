from functools import cache
from pathlib import Path

import requests
from bs4 import BeautifulSoup, Tag

from modules.exceptions import VersionNotFoundError
from modules.updaters.GenericUpdater import GenericUpdater
from modules.utils import parse_hash, sha256_hash_check

DOMAIN = "https://cdimage.debian.org"
DOWNLOAD_PAGE_URL = f"{DOMAIN}/debian-cd/current-live/amd64/iso-hybrid/"
FILE_NAME = "debian-live-[[VER]]-amd64-[[EDITION]].iso"


class Debian(GenericUpdater):
    """
    A class representing an updater for Debian.

    Attributes:
        valid_editions (list[str]): List of valid editions to use
        edition (str): Edition to download
        download_page (requests.Response): The HTTP response containing the download page HTML.
        soup_download_page (BeautifulSoup): The parsed HTML content of the download page.
        soup_index_list (Tag): The index list containing the downloadable files.

    Note:
        This class inherits from the abstract base class GenericUpdater.
    """

    def __init__(self, folder_path: Path, edition: str) -> None:
        self.valid_editions = [
            "cinnamon",
            "gnome",
            "kde",
            "lxde",
            "lxqt",
            "mate",
            "standard",
            "xfce",
        ]

        self.edition = edition.lower()

        file_path = folder_path / FILE_NAME
        super().__init__(file_path)

        # Make the parameter case insensitive, and find back the correct case using valid_editions

        from modules.utils_network import robust_get
        from modules.utils_network_patch import get_cli_retries
        resp = robust_get(DOWNLOAD_PAGE_URL, retries=get_cli_retries(), delay=1)
        if resp is None:
            print("Debian.py HAD 403 ERROR AND CANNOT BE DOWNLOADED")
            return
        if resp.status_code != 200:
            raise ConnectionError(
                f"Failed to fetch the download page from '{DOWNLOAD_PAGE_URL}'"
            )
        self.download_page = resp
        self.soup_download_page = BeautifulSoup(
            self.download_page.content, features="html.parser"
        )

        self.soup_index_list: Tag = self.soup_download_page.find(
            "table", attrs={"id": "indexlist"}
        )  # type: ignore

        if not self.soup_index_list:
            raise ConnectionError(
                "We couldn't find the list of indexes containing the download URLs"
            )

    @cache
    def _get_download_link(self) -> str:
        return f"{DOWNLOAD_PAGE_URL}/{self._get_complete_normalized_file_path(absolute=False)}"

    def check_integrity(self) -> bool:
        sha256_url = f"{DOWNLOAD_PAGE_URL}/SHA256SUMS"

        from modules.utils_network import robust_get
        resp = robust_get(sha256_url, retries=get_cli_retries(), delay=1)
        if resp is None:
            raise ConnectionError(f"Failed to fetch SHA256SUMS from '{sha256_url}'")
        sha256_sums = resp.text
        sha256_sum = parse_hash(
            sha256_sums,
            [str(self._get_complete_normalized_file_path(absolute=False))],
            0,
        )

        return sha256_hash_check(
            self._get_complete_normalized_file_path(absolute=True),
            sha256_sum,
        )

    @cache
    def _get_latest_version(self) -> list[str]:
        download_a_tags = self.soup_index_list.find_all("a", href=True)
        if not download_a_tags:
            raise VersionNotFoundError("We were not able to parse the download page")

        latest = next(
            href
            for a_tag in download_a_tags
            if str(
                self._get_normalized_file_path(
                    absolute=False,
                    version=None,
                    edition=self.edition if self.has_edition() else None,  # type: ignore
                    lang=self.lang if self.has_lang() else None,  # type: ignore
                )
            ).split("[[VER]]")[-1]
            in (href := a_tag.get("href"))
        )

        return self._str_to_version(latest.split("-")[2])
