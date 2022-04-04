'''
    /etc/unbound/unbound-unknown2fake.py

    Required packages: unbound, python-unbound

    unbound.conf should contain:

        server:
            module-config: "validator python iterator"
        python:
            python-script: "/etc/unbound/unbound-unknown2fake.py"

    Written by ilya.evseev@gmail.com at May 2017, Dec 2017, Dec 2018
'''

FAKE_IPADDR = "172.19.25.234"

def init(id, cfg): return True
def deinit(id): return True
def inform_super(id, qstate, superqstate, qdata): return True

def is_good(qstate):

    if qstate.qinfo.qtype  != RR_TYPE_A:       return True
    if qstate.qinfo.qclass != RR_CLASS_IN:     return True
    if not qstate.return_msg:                  return False
    qflags = qstate.return_msg.rep.flags
    if qflags == 0x8083 or  qflags == 0x8183:  return False
    if qflags != 0x8080 and qflags != 0x8180:  return True
    if qstate.return_msg.rep.an_numrrsets > 0: return True
    return False

def operate(id, event, qstate, qdata):

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
        #pass the query to validator
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_MODDONE:

        qstate.ext_state[id] = MODULE_FINISHED    # ..assume good

        # TRY TO SKIP ALL EXCEPT "IN A" FAILED OR EMPTY RESPONSES..
        if is_good(qstate): return True

        qtyp  = qstate.qinfo.qtype
        qname = qstate.qinfo.qname_str

        # CREATE FAKE RESPONSE..
        log_info("unknown2fake: handle \"%s\"" % qname)
        msg = DNSMessage(qname, qtyp, RR_CLASS_IN, PKT_QR | PKT_RA) # | PKT_AA)  # AA cannot be cached
        msg.answer.append("%s %d IN A %s" % (qname, 60, FAKE_IPADDR))  # ..ttl, ipaddr

        # TRY TO SEND IT..
        qstate.ext_state[id] = MODULE_ERROR       # ..assume fail
        if not msg.set_return_msg(qstate): return True
        if not storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0): return False

        # ALL OK..
        qstate.return_rcode = RCODE_NOERROR
        qstate.return_msg.rep.security = sec_status_secure
        qstate.ext_state[id] = MODULE_FINISHED    # ..assume good
        return True

    qstate.ext_state[id] = MODULE_ERROR
    return True

log_info("unknown2fake: loaded.")
