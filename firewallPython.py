/bin/python
import nfqueue, iptables, os
from dpkt import ip

q = None

def cb(dummy, payload):
    # make decision about if the packet should be allowed. in this case, drop everything:
    payload.set_verdict(nfqueue.NF_DROP)

q = nfqueue.queue()
q.open()
q.bind()
q.set_callback(cb)
q.create_queue(1)

q.try_run()
