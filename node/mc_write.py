import json
from tornado import gen
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from urlparse import urljoin

DEFAULT_MC_API_URL='http://localhost:9002'

class MediachainWriter(object):
    """
    Writes data to a mediachain node using the HTTP API.
    If no API url is given, assumes the node is running on
    localhost with the default port (9002).
    """

    def __init__(self, mc_api_url=None):
        if mc_api_url is None:
            mc_api_url = DEFAULT_MC_API_URL

        self.api_root = mc_api_url
        self.client = AsyncHTTPClient()

    def _post(self, path, body):
        url = urljoin(self.api_root, path)
        return self.client.fetch(
            HTTPRequest(
                url=url,
                method='POST',
                body=body))

    @gen.coroutine
    def publish(self, namespace, data):
        """
        Converts `data` to json and writes to the mediachain node.
        Returns a tornado Future, which will resolve to a list of
        statment id strings.
        :param namespace: string namespace to publish to
        :param data: either a dict or a list of dicts that can be converted to JSON objects
        :return: tornado Future, will resolve to list of string statement IDs on success.
        :raise: HTTPError if request fails
        """
        if isinstance(data, list):
            objects = data
        else:
            objects = [data]

        ndjson = '\n'.join(map(json.dumps, objects))
        response = yield self._post('publish/' + namespace, ndjson)
        raise gen.Return(response.body.strip().split('\n'))
