import datetime
import socket
import time
import unbound
#import tld


ctx = unbound.ub_ctx()
ctx.resolvconf("/etc/resolv.conf")
#status, result = ctx.resolve("www.nic.cz", unbound.RR_TYPE_A, unbound.RR_CLASS_IN)


#FAKE_IPADDR = "your.redirect.ip.addr" 
FAKE_IPADDR = "your.redirect.ip.addr" 
PORT = 9000

def init(id, cfg): return True
def deinit(id): return True
def inform_super(id, qstate, superqstate, qdata): return True

def dataHex(data, prefix=""):
    res = ""
    for i in range(0, (len(data)+15)/16):
        res += "%s0x%02X | " % (prefix, i*16)
        d = map(lambda x:ord(x), data[i*16:i*16+17])
        for ch in d:
            res += "%02X " % ch
        for i in range(0,17-len(d)):
            res += "   "
        res += "| "
        for ch in d:
            if (ch < 32) or (ch > 127):
                res += ". "
            else:
                res += "%c " % ch
        res += "\n"
    return res

def is_good(qstate):

    if qstate.qinfo.qtype  != RR_TYPE_A:       return True
    log_info("Domain name :" + qstate.qinfo.qname_str)
    log_info("q-type : " + str(qstate.qinfo.qtype))
    log_info("q-class : " + str(qstate.qinfo.qclass ))
    log_info("q-return_msge:" + str(qstate.return_msg.rep.flags))
    log_info("q-return :" + str(qstate.return_rcode))

    if qstate.qinfo.qclass != RR_CLASS_IN:     return True
    if not qstate.return_msg:                  return False
    if (qstate.return_rcode) != RCODE_NOERROR: return True

    qflags = qstate.return_msg.rep.flags

    if  qflags == 0x8180:  return True
    log_info("flag :" + str(qflags))
    log_info("number of return mes:"+ str(qstate.return_msg.rep.an_numrrsets))

    if qflags == 0x8083 or  qflags == 0x8183:  return False
    if qflags != 0x8080 and qflags != 0x8180:  return True
    if qstate.return_msg.rep.an_numrrsets > 0:
        #log_info("addtional-hexdata"+dataHex(qstate.return_msg.rep.rrsets[0].entry.data[0]))
        return True

    return False


def operate(id, event, qstate, qdata):

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
        #pass the query to validator
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_MODDONE:
        qtyp  = qstate.qinfo.qtype
        qname = qstate.qinfo.qname_str
        qstate.ext_state[id] = MODULE_FINISHED    # ..assume good
        aplens_domain =""
        if len(qname) > 19:
            temp_tld = qname[-15:-1]
            aplens_subdomain = qname[:(len(qname)-16)]
            aplens_domain = temp_tld
            log_info("Domain name aplens :" + aplens_domain +":"+aplens_subdomain)

        # TRY TO SKIP ALL EXCEPT "IN A" FAILED OR EMPTY RESPONSES..
        if is_good(qstate): return True
        if qstate.return_msg.rep.an_numrrsets > 0:
            log_info(" -   ")
            log_info("addtional-hexdata 0 :"+str(qstate.return_msg.rep.rrsets[0].entry.data.count))
            log_info("addtional-hexdata 1 :"+str(qstate.return_msg.rep.rrsets[0].entry.data.count))
        if not edns_opt_list_is_empty(qstate.edns_opts_front_in):
            log_info("python: searching for EDNS option code 65001 during NEW ")
            for o in qstate.edns_opts_front_in_iter:
                if o.code == 65001:
                    log_info("python: found EDNS option code 65001")
                    # Instruct other modules to not lookup for an
                    # answer in the cache.
                    qstate.no_cache_lookup = 1
                    log_info("python: enabled no_cache_lookup")

                    # Instruct other modules to not store the answer in
                    # the cache.
                    qstate.no_cache_store = 1
                    log_info("python: enabled no_cache_store")
        if not edns_opt_list_is_empty(qstate.edns_opts_front_in):
            log_info("python: EDNS options in edns_opts_front_in:")
            for o in qstate.edns_opts_front_in_iter:
                #for y in o.data:
                #    log_info("lengis :"+o.data.decode("utf-8"))


                #ipv4-address = ip-raw-data[:8]
                log_info("ipv4----:" +(socket.inet_ntoa(o.data[-4:] )))

                log_info("python:    Code: {}, Data: '{}'".format(o.code,
                                "".join('{:02x}'.format(x) for x in o.data)))

        if qstate.return_msg.rep.an_numrrsets > 0 and qstate.return_msg.rep.rrsets[0].rk.type_str =="CNAME" :
            status, result = ctx.resolve(qstate.return_msg.rep.rrsets[0].rk.dname_str, unbound.RR_TYPE_A, unbound.RR_CLASS_IN)
            if status == 0 and result.havedata:
                cname_ip = str(result.data.address_list[0])
                log_info(str(id) + " return domain_name "+ str(qstate.return_msg.rep.rrsets[0].rk.dname_str )+":before cname- : "+ str(qname)+":"+cname_ip )
                msg = DNSMessage(qname, qtyp, RR_CLASS_IN, PKT_QR | PKT_RA) # | PKT_AA)  # AA cannot be cached
                msg.answer.append("%s %d IN A %s" % (qname, 10,result.data.address_list[0]))  # ..ttl, ipaddr
        elif aplens_domain == "aplens-name.co":
            #status, result = ctx.resolve(aplens_subdomain, unbound.RR_TYPE_A, unbound.RR_CLASS_IN)
            #if status == 0 and result.havedata:
            #    cname_ip = str(result.data.address_list[0])
            #    log_info(str(id) + " aplens sub domain_name "+ str(qstate.return_msg.rep.rrsets[0].rk.dname_str )+":before cname- >> "+ str(qname)+":"+cname_ip )
                msg = DNSMessage(aplens_subdomain, qtyp, RR_CLASS_IN, PKT_QR | PKT_RA) # | PKT_AA)  # AA cannot be cached
                msg.answer.append("%s %d IN a %s" % (qname,2 ,"34.130.15.30"))  # ..ttl, ipaddr
                #return True
             ## the user decied to go directly without APLENS. no need to process code
        else:

           ## untested-code if qstate.return_msg.rep.an_numrrsets == 0 and qstate.return_msg.rep.rrsets[0].rk.type_str =="CNAME" : return True


            # CREATE FAKE RESPONSE..
            log_info(str(id)+":NXforward: handle \"%s\"" % qname)

            date_time = datetime.datetime.now()


        # expect there is linux NC command running on port 9000 to 9009 on FAKE-IP
        # "domain {query-domain-name}" is send to remote host to generate cert and NGINX

            if len(qname.split(".")) > 2:
                global PORT
                if PORT == 9009:
                    PORT = 9000
                else:
                    PORT += 1
                log_info("Handled by port " + str(PORT))
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                try:
                    s.connect((FAKE_IPADDR, PORT))
                    res = s.sendall(str.encode("domain " + qstate.return_msg.qinfo.qname_str[:-1]))
                    if res == None:
                        s.close()
                        time.sleep(0.8)
                        # wait 0.8s for digi cert generation
                except:
                    s.close()

            msg = DNSMessage(qname, qtyp, RR_CLASS_IN, PKT_QR | PKT_RA) # | PKT_AA)  # AA cannot be cached
            ## code for domain requery : hashset.add(hash(qname))
            msg.answer.append("%s %d IN A %s" % (qname, 1, FAKE_IPADDR))  # ..ttl, ipaddr

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
log_info("NXforward: loaded.")
