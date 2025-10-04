import time
import requests
import logging
from typing import Any, Optional

def robust_get(url: str, retries: int = 3, delay: float = 1.0, **kwargs) -> Optional[requests.Response]:
    """
    Perform a GET request with retry logic for network errors.

    Args:
        url (str): The URL to fetch.
        retries (int): Number of retries (0 = no retry, -1 = infinite, default 3).
        delay (float): Seconds to wait between retries.
        **kwargs: Passed to requests.get.

    Returns:
        requests.Response | None: The response if successful, None if all retries fail.
    """
    # Normalize retries: accept 'ALL'/'all' as infinite (-1), else int
    if isinstance(retries, str):
        if retries.lower() == 'all':
            retries = -1
        else:
            try:
                retries = int(retries)
            except Exception:
                retries = 0
    attempt = 0
    while True:
        try:
            response = requests.get(url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            # Cleanly detect real HTTP 403 (Forbidden) errors
            status_code = None
            if hasattr(e, 'response') and e.response is not None:
                status_code = e.response.status_code
            if status_code == 403:
                logging.error(f"robust_get: GET {url} failed with HTTP 403 Forbidden. Not retrying.")
                return None
            attempt += 1
            logging.warning(f"robust_get: GET {url} failed (attempt {attempt}{' (infinite)' if retries == -1 else f'/{retries}'}) - {e}")
            if retries != -1 and attempt > retries:
                logging.error(f"robust_get: Exceeded max retries for {url}")
                return None
            time.sleep(delay)
        except Exception as e:
            attempt += 1
            logging.warning(f"robust_get: GET {url} failed (attempt {attempt}{' (infinite)' if retries == -1 else f'/{retries}'}) - {e}")
            if retries != -1 and attempt > retries:
                logging.error(f"robust_get: Exceeded max retries for {url}")
                return None
            time.sleep(delay)
