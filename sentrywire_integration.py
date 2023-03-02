import json
import time
import requests
import urllib3
import re
import demistomock as demisto
from error_remover import *
from datetime import datetime
from datetime import timedelta
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

TOKEN_MAX_AGE = 28800
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
PORT = 41395
API_VERSION = "v3"

''' SENTRYWIRE ADAPTER CLASS '''


class SentryWireAdapter(object):

    def __init__(
            self,
            ip: str,
            port: int = PORT,
            api_version: str = API_VERSION,
            retry_transient_errors: bool = False,
            verify: bool = False
            ):
        # Create a session object for requests
        self.session = requests.Session()
        self._ip = ip
        self._port = port
        self._version = api_version
        self._retry_transient_errors = retry_transient_errors
        self._verify = verify

    def build_url(self, path: str) -> str:
        return "https://%s:%s/%s%s" % (self._ip, self._port, self._version, path)

    @staticmethod
    def _prepare_send_data(
            files: dict = None,
            post_data: dict = None,
            raw: bool = False,
    ):
        if files:
            return None, files, "multipart/form-data"

        if raw and post_data:
            return None, post_data, "application/octet-stream"

        return post_data, None, "application/json"

    def http_request(
            self,
            method: str,
            path: str,
            params: dict = None,
            post_data: dict = None,
            raw: bool = False,
            files: dict = None,
            timeout: float = None,
            max_retries: int = 10,
            **kwargs):

        url = self.build_url(path)

        json, data, content_type = self._prepare_send_data(files, post_data, raw)

        if files:
            req = requests.Request(method, url, json=json, data=data, params=params, files=files)
        else:
            req = requests.Request(method, url, json=json, data=data, params=params)

        prepped = self.session.prepare_request(req)
        settings = self.session.merge_environment_settings(
            prepped.url, {}, None, self._verify, None
        )

        cur_retries = 0
        while True:
            result = self.session.send(prepped, timeout=timeout, **settings)

            if 200 <= result.status_code < 300:
                return result

            retry_transient_errors = kwargs.get(
                "retry_transient_errors", self._retry_transient_errors
            )
            if result.status_code in [500, 502, 503, 504] and retry_transient_errors:
                if max_retries == -1 or cur_retries < max_retries:
                    wait_time = 2 ** cur_retries * 0.1
                    if "Retry-After" in result.headers:
                        wait_time = int(result.headers["Retry-After"])
                    cur_retries += 1
                    time.sleep(wait_time)
                    continue

            error_message = result.content
            try:
                error_json = result.json()
                for k in ("message", "error", "msg"):
                    if k in error_json:
                        error_message = error_json[k]
            except (KeyError, ValueError, TypeError):
                pass
            # Error check may cause issues
            if result.status_code >= 300:
                raise Exception(error_message)
            #if result.status_code in ErrorLookupTable:
            #    if error_message:
            #        raise ErrorLookupTable[result.status_code](error_message)
            #    else:
            #        raise ErrorLookupTable[result.status_code]()
            #
            #raise SentrywireException(error_message)

    def http_delete(
            self,
            path: str,
            **kwargs) -> requests.Response():
        """Make a DELETE request to the server.
        Args:
            path (str): Path or full URL to query ('/projects' or
                        'http://whatever/v4/api/projecs')
            **kwargs: Extra options to send to the server (e.g. sudo)
        Returns:
            The requests object.
        Raises:
            GitlabHttpError: When the return code is not 2xx
        """
        result = self.http_request("delete", path, **kwargs)
        if "Content-Type" in result.headers:
            if (
                    result.headers["Content-Type"] == "application/json"
            ):
                try:
                    return result.json()
                except Exception:
                    raise "Failed to parse the server message"
            else:
                return result
        return result

    def http_get(
            self,
            path: str,
            query_data: dict = None,
            raw: bool = False,
            **kwargs
    ):
        """Make a GET request to the server.
        Args:
            path (str): Path or full URL to query ('/projects' or
                        'http://whatever/v4/api/projecs')
            query_data (dict): Data to send as query parameters
            raw (bool): If True do not try to parse the output as json
            **kwargs: Extra options to send to the server (e.g. sudo)
        Returns:
            The parsed json data.
        Raises:
            GitlabHttpError: When the return code is not 2xx
            GitlabParsingError: If the json data could not be parsed
        """
        query_data = query_data or {}
        result = self.http_request(
            "get", path, query_data=query_data, **kwargs
        )
        if "Content-Type" in result.headers:
            if (
                    result.headers["Content-Type"] == "application/json"
                    and not raw
            ):
                try:
                    return result.json()
                except Exception:
                    raise "Failed to parse the server message"
            else:
                return result

    def http_put(
            self,
            path: str,
            query_data: dict = None,
            post_data: dict = None,
            raw: bool = False,
            files: dict = None,
            **kwargs
    ):
        """Make a PUT request to the Gitlab server.
        Args:
            path (str): Path or full URL to query ('/projects' or
                        'http://whatever/v4/api/projecs')
            query_data (dict): Data to send as query parameters
            post_data (dict): Data to send in the body (will be converted to
                              json by default)
            raw (bool): If True, do not convert post_data to json
            files (dict): The files to send to the server
            **kwargs: Extra options to send to the server (e.g. sudo)
        Returns:
            The parsed json returned by the server.
        Raises:
            GitlabHttpError: When the return code is not 2xx
            GitlabParsingError: If the json data could not be parsed
        """
        query_data = query_data or {}
        post_data = post_data or {}

        result = self.http_request(
            "put",
            path,
            query_data=query_data,
            post_data=post_data,
            files=files,
            raw=raw,
            **kwargs
        )
        try:
            return result.json()
        except Exception:
            raise "Failed to parse the server message"

    def http_post(
            self,
            path: str,
            query_data: dict = None,
            post_data: dict = None,
            raw: bool = False,
            files: dict = None,
            **kwargs
    ):
        """Make a POST request to the server.
        Args:
            path (str): Path or full URL to query ('/projects' or
                        'http://whatever/v4/api/projecs')
            query_data (dict): Data to send as query parameters
            post_data (dict): Data to send in the body (will be converted to
                              json by default)
            raw (bool): If True, do not convert post_data to json
            files (dict): The files to send to the server
            **kwargs: Extra options to send to the server (e.g. sudo)
        Returns:
            The parsed json returned by the server if json is return, else the
            raw content
        Raises:
            GitlabHttpError: When the return code is not 2xx
            GitlabParsingError: If the json data could not be parsed
        """
        query_data = query_data or {}
        post_data = post_data or {}

        result = self.http_request(
            "post",
            path,
            query_data=query_data,
            post_data=post_data,
            files=files,
            raw=raw,
            **kwargs
        )
        try:
            if result.headers.get("Content-Type", None) == "application/json":
                return result.json()
        except Exception:
            raise "Failed to parse the server message"
        return result


''' SENTRYWIRE CLASS '''


class SentryWire(object):
    def __init__(self, *args):
        self.unitaddress = args[0]
        self.username = args[1]
        self.password = args[2]
        self.token = args[3]
        self.adapter = SentryWireAdapter(self.unitaddress)

    @staticmethod
    def get_search_args(args: Dict[str, Any]) -> None:
        """
        In the event that there are other functions that require argument handling, make another function like this
        Going to try using switch statement since documentation says that everything should be written in python3
        Don't put Demisto function calls in class
        1. Confirm that all required args are present (start time, end time, etc.)
        2. Handle missing args with exceptions/error messages (low priority)
        """
        try:
            # Validate search_name
            srch = str(args["search_name"]).replace('_', '')
            if not srch.isalnum():
                raise Exception(f"Search name contains invalid characters\nsearch_name:{srch}")

            # Validate begin_time
            try:
                validtime = datetime.strptime(str(args["begin_time"]), DATE_FORMAT)
            except Exception as e:
                raise Exception(f"Invalid time format{e}")

            # Validate end_time
            try:
                validtime = datetime.strptime(str(args["end_time"]), DATE_FORMAT)
            except Exception as e:
                raise Exception(f"Invalid time format{e}")

        except Exception as e:
            return_error(f"Failed to parse arguments\n{e}")


''' HELPER FUNCTIONS '''


''' COMMANDS '''


def login_command(sw: SentryWire):
    """Generates a new rest token for user

    Args:
        sw (SentryWire): SentryWire object that contains needed parameters

    Returns:
        CommandResults: Issuing information + login message
    """
    path = "/fmlogin"
    post_data = {
        "username": sw.username,
        "password": sw.password
    }
    outputs = {}
    try:
        # Login request
        response = sw.adapter.http_post(path, post_data=post_data).json()
        token = response["rest_token"]

        # Date management
        current_time = datetime.utcnow()
        token_duration = timedelta(seconds=TOKEN_MAX_AGE)
        readable_time_now = current_time.strftime(DATE_FORMAT)
        readable_time_exp = (current_time + token_duration).strftime(DATE_FORMAT)
        exp_stamp = datetime.timestamp(current_time + timedelta(seconds=TOKEN_MAX_AGE))

        # Store Token
        cached_token = {
            "rest_token": token,
            "expiration_date": exp_stamp
        }
        set_integration_context(cached_token)

        # Generate Output
        outputs = {
            "username": sw.username,
            "auth_type": "login",
            "issued": readable_time_now,
            "expires": readable_time_exp
        }
    except Exception as e:
        return_error(f'Failed to execute Login command. Error: {e}')
    return CommandResults(
        readable_output="Logged in!",
        outputs_prefix='SentryWire.Authentication',
        outputs_key_field='',
        outputs=outputs
    )


def logout_command(sw: SentryWire):
    """Purges rest token from SentryWire unit and user

        Args:
            sw (SentryWire): SentryWire object that contains needed parameters

        Returns:
            CommandResults: Logout message
        """
    path = "/fmlogout"
    outputs = {}
    try:
        # Logout request
        response = sw.adapter.http_delete(path, params={"rest_token": sw.token}).json()

        # Resetting cached token
        empty_token = {
            "rest_token": None,
            "expiration_date": 0
        }
        set_integration_context(empty_token)

        # Generate output
        outputs = {
            "username": sw.username,
            "auth_type": "logout",
        }
    except Exception as e:
        return_error(f'Failed to execute Logout command. Error: {e}')
    return CommandResults(
        readable_output="Logged out!",
        outputs_prefix='SentryWire.Authentication',
        outputs_key_field='',
        outputs=outputs
    )


def create_search_command(sw: SentryWire, args: Dict[str, Any]):
    """Creates a search on SentryWire unit

        Args:
            sw (SentryWire): SentryWire object that contains needed parameters
            args (Dict[str, Any]): User args entered from CLI

        Returns:
            CommandResults: Response from SentryWire unit
    """
    path = "/fmsearch"
    sw.get_search_args(args)
    post_data = {
        "rest_token": sw.token,
        "search_name": args["search_name"],
        "search_filter": args["search_filter"],
        "begin_time": args["begin_time"],
        "end_time": args["end_time"]
    }
    if "target_list" in args.keys():
        post_data["targetlist"] = args["target_list"]
    if "max_packets" in args.keys():
        post_data["max_packets"] = args["max_packets"]
    readable_output, response = "", ""
    try:
        # Search request
        response = sw.adapter.http_post(path, post_data=post_data)

        # Extract search_id
        search_id = re.search("searchname=(.*?)&", response[0]["checkstatus"]).group(1)

        # Make links into something readable
        readable_output += f"search_id : {search_id}\n"

        # CHANGE ME!
        # This should be enabled/disabled using flags
        for key in response[0]:
            value = str(response[0][key])
            readable_output += f"{key} : {value}\n"
        readable_output = readable_output[:-1]

        # Extracts search_id from one of the links
        response[0]['search_id'] = search_id
    except Exception as e:
        return_error(f"Failed to create search: {e}")
    # the search_id is in the output field because it may need to be accessed for automation purposes
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SentryWire.Search.History',
        outputs_key_field='search_id',
        outputs=response
    )


def delete_search_command(sw: SentryWire, args: Dict[str, Any]):
    """Deletes search from SentryWire unit

        Args:
            sw (SentryWire): SentryWire object that contains needed parameters
            args (Dict[str, Any]): User args entered from CLI

        Returns:
            CommandResult: response from SentryWire unit
    """
    path = "/fmsearch"
    search_id = args["search_id"]
    params = {
        "rest_token": sw.token,
        "searchname": search_id
    }
    readable_output, response = "", ""
    try:
        # Delete request
        response = sw.adapter.http_delete(path, params=params)

        # Add search_id
        response["search_id"] = search_id
    except Exception as e:
        return_error(f"Failed to delete search: {e}")
    return CommandResults(
        readable_output=f"{search_id} has been deleted!",
        outputs_prefix='SentryWire.Search.Deleted',
        outputs_key_field='search_id',
        outputs=response
    )


def download_pcap_command(sw: SentryWire, args: Dict[str, Any]):
    """Downloads pcap file from url

        Args:
            args (Dict[str, Any]): User args entered from CLI

        Returns:
            fileResult: Filed saved to xSOAR
    """
    file_entry = None
    try:
        # url = args['url']
        # search_id = re.search("searchname=(.*?)&", url).group(1)
        search_id = args['search_id']
        nodename = args['node_name']
        url = f"https://{sw.unitaddress}:{PORT}/{API_VERSION}/fnmetadata" \
              f"?rest_token={sw.token}" \
              f"&searchname={search_id}" \
              f"&nodename={nodename}"

        # Download request
        file_entry = fileResult(f'{search_id}.pcap', requests.get(url, verify=False).content)
    except Exception as e:
        return_error(f'Failed to save file: {e}')
    return_results(file_entry)


def download_metadata_command(sw: SentryWire, args: Dict[str, Any]):
    """Downloads metadata zip file from url

        Args:
            args (Dict[str, Any]): User args entered from CLI

        Returns:
            fileResult: Filed saved to xSOAR
    """
    file_entry = None
    try:
        # url = args['url']
        # search_id = re.search("searchname=(.*?)&", url).group(1)
        search_id = args['search_id']
        nodename = args['node_name']
        url = f"https://{sw.unitaddress}:{PORT}/{API_VERSION}/fnmetadata" \
              f"?rest_token={sw.token}" \
              f"&searchname={search_id}" \
              f"&nodename={nodename}"

        # Download request
        file_entry = fileResult(f'{search_id}.zip', requests.get(url, verify=False).content)
    except Exception as e:
        return_error(f'Failed to save file: {e}')
    return_results(file_entry)


def download_object_list_command(sw: SentryWire, args: Dict[str, Any]):
    """Downloads object list zip file from url

        Args:
            sw (SentryWire): SentryWire object that contains needed parameters
            args (Dict[str, Any]): User args entered from CLI

        Returns:
            fileResult: Filed saved to xSOAR
    """
    path = "/fmsearch/data"
    data_type = "ObjectList"
    search_id = args["search_id"]
    params = {
        "rest_token": sw.token,
        "searchname": search_id,
        "type": data_type,
        "nodename": args["node_name"]
    }
    file_entry = None
    try:
        # Download request
        file_entry = fileResult(f'{search_id}_object_list.zip', sw.adapter.http_get(path, params=params).content)
    except Exception as e:
        return_error(f"Failed to download object list: {e}")
    return_results(file_entry)


def download_object_data_command(sw: SentryWire, args: Dict[str, Any]):
    """Downloads object(s) zip file from url

        Args:
            sw (SentryWire): SentryWire object that contains needed parameters
            args (Dict[str, Any]): User args entered from CLI

        Returns:
            fileResult: Filed saved to xSOAR
    """
    path = "/fmsearch/data"
    data_type = "SearchObjects"
    search_id = args["search_id"]
    params = {
        "rest_token": sw.token,
        "searchname": search_id,
        "type": data_type,
        "nodename": args["node_name"]
    }
    file_entry = None
    try:
        # Download request
        file_entry = fileResult(f'{search_id}_object(s).zip', sw.adapter.http_get(path, params=params).content)
        assert file_entry
    except Exception as e:
        return_error(f"Failed to download object(s): {e}")
    return_results(file_entry)


def get_search_status_command(sw: SentryWire, args: Dict[str, Any]):
    """Get search status from SentryWire unit

        Args:
            args (Dict[str, Any]): User args entered from CLI

        Returns:
            CommandResults: Response from SentryWire unit
    """
    readable_output, response = "", ""
    try:
        search_id = args['search_id']
        nodename = args['node_name']
        url = f"https://{sw.unitaddress}:{PORT}/{API_VERSION}/fnsearchstatus" \
              f"?rest_token={sw.token}" \
              f"&searchname={search_id}" \
              f"&nodename={nodename}"

        # Status request
        response = requests.get(url, verify=False).json()

        # Add search_id
        response["search_id"] = re.search("searchname=(.*?)&", url).group(1)

        # Parse status
        if "SearchResult" in response:
            results = response["SearchResult"]
            readable_output = f"Search completed: {results}"
        else:
            results = response["SearchStatus"]
            readable_output = f"Search status: {results}"
    except Exception as e:
        return_error(f'Failed to get search status: {e}')
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SentryWire.Search.Status',
        outputs_key_field='search_id',
        outputs=response
    )


def get_server_status_command(sw: SentryWire):
    path = "/fmping"
    params = {
        "rest_token": sw.token,
    }
    readable_output, response = "", ""
    try:
        response = sw.adapter.http_get(path, params=params)
        status = json.loads(response["ServerInfo"])["Status"]
        readable_output = f"{sw.unitaddress}: {status}"
    except Exception as e:
        return_error(f'Failed to get server status: {e}')
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SentryWire.Server',
        outputs_key_field='',
        outputs=response
    )


def test_module(sw: SentryWire) -> str:
    # Replace with a request to the fmping endpoint
    try:
        login_command(sw)
        cached_token = get_integration_context()
        sw.token = json.loads(cached_token)["rest_token"]
        tmp = get_server_status_command(sw)
        logout_command(sw)
    except Exception as e:
        return_error(f'Failed to execute test-module command. Error: {str(e)}')
    return 'ok'


def main() -> None:
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    try:
        # SETUP
        assert demisto.params()
        unitaddress = demisto.params().get('unitaddress')
        username = demisto.params().get('credentials').get('identifier')
        password = demisto.params().get('credentials').get('password')
        cached_token = get_integration_context()
        if not cached_token:
            cached_token = {
                "rest_token": None,
                "expiration_date": 0
            }
        sw = SentryWire(unitaddress, username, password, cached_token["rest_token"])
        demisto.debug(f'Command being called is {demisto.command()}')
        current_time = datetime.timestamp(datetime.utcnow())

        # TEST MODULE
        if demisto.command() == "test-module":
            return_results(test_module(sw))

        # AUTHENTICATION - NO TOKEN REQUIRED
        # COMMANDS:
        # LOGIN
        if demisto.command() == "sentrywire-login":
            return_results(login_command(sw))
        # LOGOUT
        if demisto.command() == "sentrywire-logout":
            assert cached_token["rest_token"]
            return_results(logout_command(sw))

        # INVESTIGATOR - TOKEN REQUIRED
        # COMMANDS:
        # GET PCAP
        if demisto.command() == "sentrywire-get-pcap":
            if current_time > cached_token["expiration_date"]:
                return_error("token has expired")
            return_results(download_pcap_command(sw, demisto.args()))
        # GET METADATA
        if demisto.command() == "sentrywire-get-metadata":
            if current_time > cached_token["expiration_date"]:
                return_error("token has expired")
            return_results(download_metadata_command(sw, demisto.args()))
        # GET SEARCH STATUS
        if demisto.command() == "sentrywire-get-search-status":
            if current_time > cached_token["expiration_date"]:
                return_error("token has expired")
            return_results(get_search_status_command(sw, demisto.args()))
        # CREATE SEARCH
        if demisto.command() == "sentrywire-create-search":
            if current_time > cached_token["expiration_date"]:
                return_error("token has expired")
            return_results(create_search_command(sw, demisto.args()))
        # DELETE SEARCH
        if demisto.command() == "sentrywire-delete-search":
            if current_time > cached_token["expiration_date"]:
                return_error("token has expired")
            return_results(delete_search_command(sw, demisto.args()))
        # GET OBJECT LIST
        if demisto.command() == "sentrywire-get-object-list":
            if current_time > cached_token["expiration_date"]:
                return_error("token has expired")
            return_results(download_object_list_command(sw, demisto.args()))
        # GET OBJECT(S)
        if demisto.command() == "sentrywire-get-object-data":
            if current_time > cached_token["expiration_date"]:
                return_error("token has expired")
            return_results(download_object_data_command(sw, demisto.args()))
        # GET SERVER STATUS
        if demisto.command() == "sentrywire-get-server-status":
            if current_time > cached_token["expiration_date"]:
                return_error("token has expired")
            return_results(get_server_status_command(sw))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command\n{e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

