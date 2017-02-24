#!/usr/bin/env python

DEFAULT_MC_API_URL='http://localhost:9002'


import json
import cbor
import base64
from tornado import gen
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from urlparse import urljoin
from tornado.ioloop import IOLoop


def ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def ensure_unicode(val):
    if isinstance(val, basestring):
        return unicode(val)
    if isinstance(val, dict):
        new = {}
        for k, v in val.iteritems():
            new[ensure_unicode(k)] = ensure_unicode(v)
        return new
    if isinstance(val, list):
        return map(ensure_unicode, val)
    return val


def encode_object(obj):
    obj = ensure_unicode(obj)
    return base64.b64encode(cbor.dumps(obj))


class MediachainWriter(object):
    """
    Writes data to a mediachain node using the HTTP API.
    If no API url is given, assumes the node is running on
    localhost with the default port (9002).
    """

    def __init__(self,
                 mc_api_url = False,
                 default_namespace = False,
                 ):
        if mc_api_url is False:
            mc_api_url = DEFAULT_MC_API_URL
        self.mc_api_url = mc_api_url
        
        self.default_namespace = default_namespace

        self.client = AsyncHTTPClient()

    def _post(self, path, body):
        url = urljoin(self.mc_api_url, path)
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
    def publish(self, namespace=False, data=False, refs=None, deps=None, tags=None):
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
        if namespace is False:
            namespace = self.default_namespace
        
        assert namespace is not False
        assert data is not False
        
        object_ref = yield self.put_data(data)
        stmt = {'object': object_ref,
                'refs': ensure_list(refs),
                'deps': ensure_list(deps),
                'tags': ensure_list(tags)}

        response = yield self._post('publish/' + namespace, json.dumps(stmt))
        raise gen.Return(response.body.strip())

def test_mc_simple():
    print ('test_mc_write()')
        
    w = MediachainWriter()
    
    rr = IOLoop.current().run_sync(lambda: w.publish('scratch.pytest', {'hello': 'from_python'}))
    
    print ('GOT', rr)

from threading import current_thread,Thread
from Queue import Queue
from time import sleep

class MediachainQueue:
    """ 
    Convenience threaded background pusher. Especially useful when you don't already have a tornado event loop.
    Can be used as a context manager, to ensure all items are pushed prior to exit.
    
    NOTES:
    - Didn't bother to make this parallel for now, but could be easily done.
    - Unneeded at this point, but could do either of:
      + Add an `out_q` to push back permanent failures.
      + Immediately return request_ids that can be polled later for result status.
    """
    
    def __init__(self,
                 mc_api_url = False,
                 default_namespace = False,
                 sleep_time = 0.1,
                 max_size = 0,
                 ):
        """ Set max_size to > 0 to throttle input. """
        self.sleep_time_orig = sleep_time
        self.sleep_time = sleep_time
        self.in_q = Queue(max_size)
        self.mw = MediachainWriter(mc_api_url = mc_api_url,
                                   default_namespace = default_namespace,
                                   )
        self.start()
    
    def start(self):
        self.t = Thread(target = self.worker)
        self.t.daemon = True
        self.t.start()
    
    def push(self, *args, **kw):
        self.in_q.put((args, kw))

    def worker(self):
        io_loop = IOLoop()
        io_loop.start()
        while True:
            args, kw = self.in_q.get(block = True)
            io_loop.run_sync(lambda: self.mw.publish(*args, **kw))
    
    def wait_for_completion(self):
        while True:
            if not self.in_q.size():
                break
            sleep(self.sleep_time)

    def __enter__(self):
        pass
    
    def __exit__(self):
        self.wait_for_completion()
    
    def __del__(self):
        self.wait_for_completion()
        

def test_mc_threaded():
    print ('test_mc_write()')

    print 'STARTING...'
    
    with MediachainQueue() as mcq:
        for x in xrange(10):
            mcq.put('test_namespace', {'hello': 'from_python_' + str(x)})

        print 'WAITING FOR EXIT..'

    print ('DONE')


if __name__ == '__main__':
    test_mc_simple()
    test_mc_threaded()
