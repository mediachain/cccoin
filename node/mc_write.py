import json
import cbor
import base64
from tornado import gen
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from urlparse import urljoin

DEFAULT_MC_API_URL='http://localhost:9002'

def ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def ensure_unicode_dict(d):
    new = {}
    for k, v in d.iteritems():
        k = unicode(k)
        if isinstance(v, dict):
            v = ensure_unicode_dict(v)
        elif isinstance(v, basestring):
            v = unicode(v)
        new[k] = v
    return new

def encode_object(obj):
    obj = ensure_unicode_dict(obj)
    return base64.b64encode(cbor.dumps(obj))

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
    def put_data(self, obj):
        """
        Store a data object in the mediachain node
        :param obj: a data object dict to encode and add to the node
        :return: tornado future that resolves to object multihash string
        """
        encoded = encode_object(obj)
        req = json.dumps({'data': encoded})
        result = yield self._post('data/put', req)
        obj_hash = result.body.strip()
        print('put object, hash: ', obj, obj_hash)
        raise gen.Return(obj_hash)


    @gen.coroutine
    def publish(self, namespace, data, refs=None, deps=None, tags=None):
        """
        Converts `data` to CBOR and writes it, and a statement referencing it,
        to the mediachain node.
        Returns a tornado Future, which will resolve to a string statement ID.
        :param namespace: string namespace to publish to
        :param data: a dict that will be encoded to CBOR and used as the "object" of the MC statement.
        :param refs: a string or list of strings to use as "WKI"s (external ids) for the statement. e.g. the cccoin post id
        :param deps: if the statement depends on other data objects, `deps` should contain their hashes
        :param tags: string or list of strings to use as keywords for queries
        :return: tornado Future, will resolve to a string statement ID on success.
        :raise: HTTPError if request fails
        """

        object_ref = yield self.put_data(data)
        stmt = {'object': object_ref,
                'refs': ensure_list(refs),
                'deps': ensure_list(deps),
                'tags': ensure_list(tags)}

        response = yield self._post('publish/' + namespace, json.dumps(stmt))
        raise gen.Return(response.body.strip())
